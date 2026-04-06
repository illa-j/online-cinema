import re

from fastapi import HTTPException, status
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from database import MovieModel
from repositories.movies import create_movie, get_movie_by_id_with_all_related_fields, get_movies, get_movies_quantity
from schemas import MovieListResponseSchema, MovieListItemSchema, MovieCreateSchema

CONSTRAINT_ERRORS = {
    "unique_movie_constraint": (
        409,
        "Movie with same name, year and duration already exists.",
    ),
    "check_imdb_range": (422, "imdb must be between 0 and 10."),
    "check_votes_non_negative": (422, "votes must be non-negative."),
    "check_meta_score_range": (422, "meta_score must be between 0 and 100."),
    "check_gross_non_negative": (422, "gross must be non-negative."),
    "check_price_non_negative": (422, "price must be non-negative."),
}


def extract_constraint_name(err):
    orig = getattr(err, "orig", None)
    if hasattr(orig, "constraint_name"):
        return orig.constraint_name
    diag = getattr(orig, "diag", None)
    if diag and getattr(diag, "constraint_name", None):
        return diag.constraint_name
    msg = str(orig) if orig else str(err)

    patterns = [
        r'constraint "([^"]+)"',
        r"UNIQUE constraint failed: (.+)",
        r"CHECK constraint failed: (.+)",
    ]

    for pattern in patterns:
        match = re.search(pattern, msg, flags=re.IGNORECASE)
        if match:
            return match.group(1).strip()

    return None


async def get_movie_list_service(
    page: int,
    per_page: int,
    db: AsyncSession,
) -> MovieListResponseSchema:
    offset = (page - 1) * per_page

    total_items = await get_movies_quantity(db)

    if not total_items:
        raise HTTPException(status_code=404, detail="No movies found.")

    movies = await get_movies(db, offset, per_page)

    if not movies:
        raise HTTPException(status_code=404, detail="No movies found.")

    movie_list = [MovieListItemSchema.model_validate(movie) for movie in movies]

    total_pages = (total_items + per_page - 1) // per_page

    response = MovieListResponseSchema(
        movies=movie_list,
        prev_page=(
            f"/api/v1/movies/?page={page - 1}&per_page={per_page}" if page > 1 else None
        ),
        next_page=(
            f"/api/v1/movies/?page={page + 1}&per_page={per_page}"
            if page < total_pages
            else None
        ),
        total_pages=total_pages,
        total_items=total_items,
    )
    return response


async def create_movie_service(
    movie_data: MovieCreateSchema, db: AsyncSession
) -> MovieModel:
    try:
        movie = await create_movie(db, movie_data)
        await db.commit()
    except IntegrityError as e:
        await db.rollback()
        constraint_name = extract_constraint_name(e)
        if constraint_name and constraint_name in CONSTRAINT_ERRORS:
            status_code, detail = CONSTRAINT_ERRORS[constraint_name]
            raise HTTPException(status_code=status_code, detail=detail)
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid input data."
        )
    except SQLAlchemyError as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected database error occurred.",
        ) from e
    return movie


async def get_movie_detail_service(movie_id: int, db: AsyncSession) -> MovieModel:
    movie = await get_movie_by_id_with_all_related_fields(db, movie_id)
    if not movie:
        raise HTTPException(status_code=404, detail="Movie not found.")
    return movie


async def delete_movie_service(movie_id: int, db: AsyncSession) -> None:
    movie = await get_movie_by_id_with_all_related_fields(db, movie_id)
    if not movie:
        raise HTTPException(status_code=404, detail="Movie not found.")
    await db.delete(movie)
    await db.commit()
