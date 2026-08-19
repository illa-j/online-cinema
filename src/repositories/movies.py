from sqlalchemy import desc, func, or_, select
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
from core.constants import ALLOWED_SORT_FIELDS


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


async def get_movies(
    db: AsyncSession,
    offset: int,
    per_page: int,
    name: str | None,
    description: str | None,
    certification: str | None,
    genre: str | None,
    star: str | None,
    director: str | None,
    year_min: int | None,
    year_max: int | None,
    time_min: int | None,
    time_max: int | None,
    imdb_min: float | None,
    imdb_max: float | None,
    votes_min: int | None,
    votes_max: int | None,
    meta_score_min: int | None,
    meta_score_max: int | None,
    gross_min: int | None,
    gross_max: int | None,
    order_by: str | None,
) -> list[MovieModel]:
    stmt = select(MovieModel)

    search_conditions = []
    if name:
        search_conditions.append(MovieModel.name.ilike(f"%{name}%"))
    if description:
        search_conditions.append(MovieModel.description.ilike(f"%{description}%"))
    if search_conditions:
        stmt = stmt.where(or_(*search_conditions))

    if certification:
        stmt = stmt.where(MovieModel.certification.has(name=certification))

    if genre:
        stmt = stmt.where(MovieModel.genres.any(GenreModel.name.ilike(f"%{genre}%")))

    if star:
        stmt = stmt.where(MovieModel.stars.any(StarModel.name.ilike(f"%{star}%")))

    if director:
        stmt = stmt.where(
            MovieModel.directors.any(DirectorModel.name.ilike(f"%{director}%"))
        )

    if year_min is not None:
        stmt = stmt.where(MovieModel.year >= year_min)
    if year_max is not None:
        stmt = stmt.where(MovieModel.year <= year_max)
    if time_min is not None:
        stmt = stmt.where(MovieModel.time >= time_min)
    if time_max is not None:
        stmt = stmt.where(MovieModel.time <= time_max)
    if imdb_min is not None:
        stmt = stmt.where(MovieModel.imdb >= imdb_min)
    if imdb_max is not None:
        stmt = stmt.where(MovieModel.imdb <= imdb_max)
    if votes_min is not None:
        stmt = stmt.where(MovieModel.votes >= votes_min)
    if votes_max is not None:
        stmt = stmt.where(MovieModel.votes <= votes_max)
    if meta_score_min is not None:
        stmt = stmt.where(MovieModel.meta_score >= meta_score_min)
    if meta_score_max is not None:
        stmt = stmt.where(MovieModel.meta_score <= meta_score_max)
    if gross_min is not None:
        stmt = stmt.where(MovieModel.gross >= gross_min)
    if gross_max is not None:
        stmt = stmt.where(MovieModel.gross <= gross_max)

    if order_by is not None:
        if order_by.startswith("-"):
            sort_field = ALLOWED_SORT_FIELDS.get(order_by.lstrip("-"))
            if sort_field:
                stmt = stmt.order_by(desc(sort_field))
        else:
            sort_field = ALLOWED_SORT_FIELDS.get(order_by)
            if sort_field:
                stmt = stmt.order_by(sort_field)
    else:
        default_order = MovieModel.default_order_by()
        if default_order:
            stmt = stmt.order_by(*default_order)

    stmt = stmt.offset(offset).limit(per_page)
    result_movies = await db.execute(
        stmt.options(
            selectinload(MovieModel.genres),
            selectinload(MovieModel.certification),
            selectinload(MovieModel.stars),
            selectinload(MovieModel.directors),
        )
    )
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
