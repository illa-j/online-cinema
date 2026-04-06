from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from database import (
    MovieModel,
    GenreModel,
    CertificationModel,
    StarModel,
    DirectorModel,
)
from schemas import MovieCreateSchema, MovieUpdateSchema, MoviePartiallyUpdateSchema


async def get_genre_by_id(db: AsyncSession, genre_id: int):
    stmt = select(GenreModel).where(GenreModel.id == genre_id)
    result = await db.execute(stmt)
    return result.scalars().first()


async def get_genre_by_ids(db: AsyncSession, genre_ids: list[int]) -> list[GenreModel]:
    stmt = select(GenreModel).where(GenreModel.id.in_(genre_ids))
    result = await db.execute(stmt)
    return result.scalars().all()


async def get_genre_by_name(db: AsyncSession, name: str):
    stmt = select(GenreModel).where(GenreModel.name == name)
    result = await db.execute(stmt)
    return result.scalars().first()


async def create_genre(db: AsyncSession, name: str):
    new_genre = GenreModel(name=name)
    db.add(new_genre)
    await db.flush()
    await db.refresh(new_genre)
    return new_genre


async def get_certification_by_id(db: AsyncSession, certification_id: int):
    stmt = select(CertificationModel).where(CertificationModel.id == certification_id)
    result = await db.execute(stmt)
    return result.scalars().first()


async def get_certification_by_ids(
    db: AsyncSession, certification_ids: list[int]
) -> list[CertificationModel]:
    stmt = select(CertificationModel).where(
        CertificationModel.id.in_(certification_ids)
    )
    result = await db.execute(stmt)
    return result.scalars().all()


async def get_certification_by_name(db: AsyncSession, name: str):
    stmt = select(CertificationModel).where(CertificationModel.name == name)
    result = await db.execute(stmt)
    return result.scalars().first()


async def create_certification(db: AsyncSession, name: str):
    new_certification = CertificationModel(name=name)
    db.add(new_certification)
    await db.flush()
    await db.refresh(new_certification)
    return new_certification


async def get_star_by_id(db: AsyncSession, star_id: int):
    stmt = select(StarModel).where(StarModel.id == star_id)
    result = await db.execute(stmt)
    return result.scalars().first()


async def get_star_by_ids(db: AsyncSession, star_ids: list[int]) -> list[StarModel]:
    stmt = select(StarModel).where(StarModel.id.in_(star_ids))
    result = await db.execute(stmt)
    return result.scalars().all()


async def get_star_by_name(db: AsyncSession, name: str):
    stmt = select(StarModel).where(StarModel.name == name)
    result = await db.execute(stmt)
    return result.scalars().first()


async def create_star(db: AsyncSession, name: str):
    new_star = StarModel(name=name)
    db.add(new_star)
    await db.flush()
    await db.refresh(new_star)
    return new_star


async def get_director_by_id(db: AsyncSession, director_id: int):
    stmt = select(DirectorModel).where(DirectorModel.id == director_id)
    result = await db.execute(stmt)
    return result.scalars().first()


async def get_director_by_ids(
    db: AsyncSession, director_ids: list[int]
) -> list[DirectorModel]:
    stmt = select(DirectorModel).where(DirectorModel.id.in_(director_ids))
    result = await db.execute(stmt)
    return result.scalars().all()


async def get_director_by_name(db: AsyncSession, name: str):
    stmt = select(DirectorModel).where(DirectorModel.name == name)
    result = await db.execute(stmt)
    return result.scalars().first()


async def create_director(db: AsyncSession, name: str):
    new_director = DirectorModel(name=name)
    db.add(new_director)
    await db.flush()
    await db.refresh(new_director)
    return new_director


async def get_movies(db: AsyncSession, offset: int, per_page: int) -> list[MovieModel]:
    order_by = MovieModel.default_order_by()
    stmt = select(MovieModel)
    if order_by:
        stmt = stmt.order_by(*order_by)
    stmt = stmt.offset(offset).limit(per_page)

    result_movies = await db.execute(stmt)
    return result_movies.scalars().all()


async def get_movies_quantity(db: AsyncSession) -> int:
    count_stmt = select(func.count(MovieModel.id))
    result_count = await db.execute(count_stmt)
    total_items = result_count.scalar() or 0
    return total_items


async def get_movie_by_id_with_all_related_fields(
    db: AsyncSession, movie_id: int
) -> MovieModel | None:
    stmt = (
        select(MovieModel)
        .where(MovieModel.id == movie_id)
        .options(
            selectinload(MovieModel.genres),
            selectinload(MovieModel.certification),
            selectinload(MovieModel.stars),
            selectinload(MovieModel.directors),
        )
    )
    result = await db.execute(stmt)
    return result.scalars().first()


async def create_movie(db: AsyncSession, movie_data: MovieCreateSchema) -> MovieModel:
    new_movie = MovieModel(
        name=movie_data.name,
        year=movie_data.year,
        time=movie_data.time,
        imdb=movie_data.imdb,
        votes=movie_data.votes,
        meta_score=movie_data.meta_score,
        gross=movie_data.gross,
        description=movie_data.description,
        price=movie_data.price,
    )

    certification = await get_certification_by_name(db, movie_data.certification_name)
    if not certification:
        certification = await create_certification(
            db, name=movie_data.certification_name
        )
    new_movie.certification = certification

    genres = []
    for genre_name in movie_data.genre_names:
        genre = await get_genre_by_name(db, genre_name)
        if not genre:
            genre = await create_genre(db, name=genre_name)
        genres.append(genre)
    new_movie.genres = genres

    stars = []
    for star_name in movie_data.star_names:
        star = await get_star_by_name(db, star_name)
        if not star:
            star = await create_star(db, name=star_name)
        stars.append(star)
    new_movie.stars = stars

    directors = []
    for director_name in movie_data.director_names:
        director = await get_director_by_name(db, director_name)
        if not director:
            director = await create_director(db, name=director_name)
        directors.append(director)
    new_movie.directors = directors

    db.add(new_movie)
    await db.flush()
    new_movie = await get_movie_by_id_with_all_related_fields(db, new_movie.id)
    return new_movie


async def update_movie(
    db: AsyncSession, movie: MovieModel, movie_data: MovieUpdateSchema
) -> MovieModel:
    for field, value in movie_data.model_dump(
        exclude={"certification_id", "genre_ids", "star_ids", "director_ids"}
    ).items():
        setattr(movie, field, value)

    await db.flush()
    updated_movie = await get_movie_by_id_with_all_related_fields(db, movie.id)
    return updated_movie


async def partially_update_movie(
    db: AsyncSession, movie: MovieModel, movie_data: MoviePartiallyUpdateSchema
) -> MovieModel:
    for field, value in movie_data.model_dump(
        exclude={"certification_id", "genre_ids", "star_ids", "director_ids"}
    ).items():
        if value is not None:
            setattr(movie, field, value)

    await db.flush()
    updated_movie = await get_movie_by_id_with_all_related_fields(db, movie.id)
    return updated_movie
