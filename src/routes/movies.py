from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from config.dependencies import require_roles
from database import UserGroupEnum, UserModel, get_db
from schemas import (
    MovieListResponseSchema,
    MovieDetailSchema,
    MovieCreateSchema,
    MovieUpdateSchema,
    MoviePartiallyUpdateSchema,
)
from services.movies import (
    create_movie_service,
    delete_movie_service,
    get_movie_detail_service,
    get_movie_list_service,
    partially_update_movie_service,
    update_movie_service,
)

router = APIRouter()


@router.get(
    "/",
    response_model=MovieListResponseSchema,
    summary="Get a paginated list of movies",
    description=(
        "<h3>This endpoint retrieves a paginated list of movies from the database. "
        "Clients can specify the `page` number and the number of items per page using `per_page`. "
        "The response includes details about the movies, total pages, and total items, "
        "along with links to the previous and next pages if applicable.</h3>"
    ),
    responses={
        404: {
            "description": "No movies found.",
            "content": {
                "application/json": {"example": {"detail": "No movies found."}}
            },
        }
    },
)
async def get_movie_list(
    page: int = Query(1, ge=1, description="Page number (1-based index)"),
    per_page: int = Query(10, ge=1, le=20, description="Number of items per page"),
    db: AsyncSession = Depends(get_db),
):
    """
    Fetch a paginated list of movies from the database (asynchronously).

    This function retrieves a paginated list of movies, allowing the client to specify
    the page number and the number of items per page. It calculates the total pages
    and provides links to the previous and next pages when applicable.

    :param page: The page number to retrieve (1-based index, must be >= 1).
    :type page: int
    :param per_page: The number of items to display per page (must be between 1 and 20).
    :type per_page: int
    :param db: The async SQLAlchemy database session (provided via dependency injection).
    :type db: AsyncSession

    :return: A response containing the paginated list of movies and metadata.
    :rtype: MovieListResponseSchema

    :raises HTTPException: Raises a 404 error if no movies are found for the requested page.
    """
    return await get_movie_list_service(page=page, per_page=per_page, db=db)


@router.post(
    "/",
    response_model=MovieDetailSchema,
    status_code=status.HTTP_201_CREATED,
    summary="Add a new movie",
    description=(
        "<h3>This endpoint allows admins or moderators to add a new movie to the database. "
        "It accepts details such as name, date, genres, actors, languages, and "
        "other attributes. The associated country, genres, actors, and languages "
        "will be created or linked automatically.</h3>"
    ),
    responses={
        201: {
            "description": "Movie created successfully.",
        },
        400: {
            "description": "Invalid input.",
            "content": {
                "application/json": {"example": {"detail": "Invalid input data."}}
            },
        },
    },
)
async def create_movie(
    movie_data: MovieCreateSchema,
    current_user: UserModel = Depends(
        require_roles(UserGroupEnum.ADMIN, UserGroupEnum.MODERATOR)
    ),
    db: AsyncSession = Depends(get_db),
):
    """
    Add a new movie to the database.

    This endpoint allows the creation of a new movie with details such as
    name, release date, genres, actors, and languages. It automatically
    handles linking or creating related entities.

    :param movie_data: The data required to create a new movie.
    :type movie_data: MovieCreateSchema
    :param db: The SQLAlchemy async database session (provided via dependency injection).
    :type db: AsyncSession

    :return: The created movie with all details.
    :rtype: MovieDetailSchema

    :raises HTTPException:
        - 409 if a movie with the same name and date already exists.
        - 400 if input data is invalid (e.g., violating a constraint).
    """
    return await create_movie_service(movie_data=movie_data, db=db)


@router.get(
    "/{movie_id}/",
    response_model=MovieDetailSchema,
    summary="Get movie details by ID",
    description=(
        "<h3>This endpoint retrieves detailed information about a specific movie by its ID. "
        "The response includes all attributes of the movie, as well as related entities such as "
        "certification, genres, stars, and directors.</h3>"
    ),
    responses={
        404: {
            "description": "Movie not found.",
            "content": {
                "application/json": {"example": {"detail": "Movie not found."}}
            },
        }
    },
)
async def get_movie_detail(movie_id: int, db: AsyncSession = Depends(get_db)):
    """
    Retrieve detailed information about a specific movie by its ID.

    This endpoint fetches a movie's details, including all attributes and related entities
    such as certification, genres, stars, and directors.

    :param movie_id: The unique identifier of the movie to retrieve.
    :type movie_id: int
    :param db: The SQLAlchemy async database session (provided via dependency injection).
    :type db: AsyncSession

    :return: Detailed information about the requested movie.
    :rtype: MovieDetailSchema

    :raises HTTPException: Raises a 404 error if the movie with the specified ID is not found.
    """
    return await get_movie_detail_service(movie_id=movie_id, db=db)


@router.put(
    "/{movie_id}/",
    response_model=MovieDetailSchema,
    summary="Update movie details by ID",
    description=(
        "<h3>This endpoint allows admins or moderators to update the details of a specific movie by its ID. "
        "Clients can provide any subset of the movie's attributes to update. The response includes the updated movie details.</h3>"
    ),
    responses={
        200: {
            "description": "Movie updated successfully.",
        },
        400: {
            "description": "Invalid input.",
            "content": {
                "application/json": {"example": {"detail": "Invalid input data."}}
            },
        },
        404: {
            "description": "Movie not found.",
            "content": {
                "application/json": {"example": {"detail": "Movie not found."}}
            },
        },
    },
)
async def update_movie(
    movie_id: int,
    movie_data: MovieUpdateSchema,
    current_user: UserModel = Depends(
        require_roles(UserGroupEnum.ADMIN, UserGroupEnum.MODERATOR)
    ),
    db: AsyncSession = Depends(get_db),
):
    """
    Update the details of a specific movie by its ID.

    This endpoint allows authorized users (admins or moderators) to update any subset of a movie's attributes.
    The response includes the updated movie details.

    :param movie_id: The unique identifier of the movie to update.
    :type movie_id: int
    :param movie_data: The data to update the movie with.
    :type movie_data: MovieCreateSchema
    :param db: The SQLAlchemy async database session (provided via dependency injection).
    :type db: AsyncSession

    :return: The updated movie details.
    :rtype: MovieDetailSchema

    :raises HTTPException:
        - 400 if input data is invalid (e.g., violating a constraint).
        - 404 if the movie with the specified ID is not found.
    """
    return await update_movie_service(movie_id=movie_id, movie_data=movie_data, db=db)


@router.patch(
    "/{movie_id}/",
    response_model=MovieDetailSchema,
    summary="Partially update movie details by ID",
    description=(
        "<h3>This endpoint allows admins or moderators to partially update the details of a specific movie by its ID. Clients can provide any subset of the movie's attributes to update. The response includes the updated movie details.</h3>"
    ),
    responses={
        200: {
            "description": "Movie updated successfully.",
        },
        400: {
            "description": "Invalid input.",
            "content": {
                "application/json": {"example": {"detail": "Invalid input data."}}
            },
        },
        404: {
            "description": "Movie not found.",
            "content": {
                "application/json": {"example": {"detail": "Movie not found."}}
            },
        },
    },
)
async def partially_update_movie(
    movie_id: int,
    movie_data: MoviePartiallyUpdateSchema,
    current_user: UserModel = Depends(
        require_roles(UserGroupEnum.ADMIN, UserGroupEnum.MODERATOR)
    ),
    db: AsyncSession = Depends(get_db),
):
    """
    Partially update the details of a specific movie by its ID.

    This endpoint allows authorized users (admins or moderators) to partially update any subset of a movie's attributes.
    The response includes the updated movie details.

    :param movie_id: The unique identifier of the movie to update.
    :type movie_id: int
    :param movie_data: The data to update the movie with.
    :type movie_data: MovieCreateSchema
    :param db: The SQLAlchemy async database session (provided via dependency injection).
    :type db: AsyncSession

    :return: The updated movie details.
    :rtype: MovieDetailSchema

    :raises HTTPException:
        - 400 if input data is invalid (e.g., violating a constraint).
        - 404 if the movie with the specified ID is not found.
    """
    return await partially_update_movie_service(
        movie_id=movie_id, movie_data=movie_data, db=db
    )


@router.delete(
    "/{movie_id}/",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a movie by ID",
    description=(
        "<h3>This endpoint allows admins or moderators to delete a specific movie by its ID. "
        "If the movie exists, it will be removed from the database. If the movie does not exist, "
        "a 404 error will be returned.</h3>"
    ),
    responses={
        204: {
            "description": "Movie deleted successfully.",
        },
        404: {
            "description": "Movie not found.",
            "content": {
                "application/json": {"example": {"detail": "Movie not found."}}
            },
        },
    },
)
async def delete_movie(
    movie_id: int,
    current_user: UserModel = Depends(
        require_roles(UserGroupEnum.ADMIN, UserGroupEnum.MODERATOR)
    ),
    db: AsyncSession = Depends(get_db),
):
    """
    Delete a specific movie by its ID.

    This endpoint allows authorized users (admins or moderators) to delete a movie from the database.
    If the movie exists, it will be removed. If it does not exist, a 404 error will be returned.

    :param movie_id: The unique identifier of the movie to delete.
    :type movie_id: int
    :param db: The SQLAlchemy async database session (provided via dependency injection).
    :type db: AsyncSession

    :raises HTTPException:
        - 204 if the movie was deleted successfully.
        - 404 if the movie with the specified ID is not found.
    """
    return await delete_movie_service(movie_id=movie_id, db=db)
