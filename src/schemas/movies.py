from datetime import datetime
from decimal import Decimal
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, Field, field_validator

from schemas.examples.movies import (
    certification_schema_example,
    director_schema_example,
    genre_schema_example,
    movie_create_schema_example,
    movie_detail_schema_example,
    movie_item_schema_example,
    movie_list_response_schema_example,
    movie_update_schema_example,
    star_schema_example,
)


class StarSchema(BaseModel):
    id: int
    name: str

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {"examples": [star_schema_example]},
    }


class GenreSchema(BaseModel):
    id: int
    name: str

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {"examples": [genre_schema_example]},
    }


class DirectorSchema(BaseModel):
    id: int
    name: Optional[str] = None

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {"examples": [director_schema_example]},
    }


class CertificationSchema(BaseModel):
    id: int
    name: str

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {"examples": [certification_schema_example]},
    }


class MovieBaseSchema(BaseModel):
    name: str = Field(..., max_length=255)
    year: int = Field(..., ge=1888)
    time: int = Field(..., gt=0)
    imdb: float = Field(..., ge=0, le=10)
    votes: int = Field(..., ge=0)
    meta_score: Optional[float] = Field(None, ge=0, le=100)
    gross: Optional[float] = Field(None, ge=0)
    description: str = Field(..., max_length=10_000)
    price: Decimal = Field(..., ge=0, max_digits=10, decimal_places=2)
    certification_id: int = Field(..., ge=1)

    model_config = {"from_attributes": True}

    @field_validator("year")
    @classmethod
    def validate_year(cls, value: int) -> int:
        current_year = datetime.now().year
        if value > current_year + 1:
            raise ValueError(f"Year cannot be greater than {current_year + 1}.")
        return value


class MovieCreateSchema(MovieBaseSchema):
    genre_ids: list[int] = Field(default_factory=list)
    star_ids: list[int] = Field(default_factory=list)
    director_ids: list[int] = Field(default_factory=list)

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {"examples": [movie_create_schema_example]},
    }


class MovieUpdateSchema(BaseModel):
    name: Optional[str] = Field(None, max_length=255)
    year: Optional[int] = Field(None, ge=1888)
    time: Optional[int] = Field(None, gt=0)
    imdb: Optional[float] = Field(None, ge=0, le=10)
    votes: Optional[int] = Field(None, ge=0)
    meta_score: Optional[float] = Field(None, ge=0, le=100)
    gross: Optional[float] = Field(None, ge=0)
    description: Optional[str] = Field(None, max_length=10_000)
    price: Optional[Decimal] = Field(None, ge=0, max_digits=10, decimal_places=2)
    certification_id: Optional[int] = Field(None, ge=1)
    genre_ids: Optional[list[int]] = None
    star_ids: Optional[list[int]] = None
    director_ids: Optional[list[int]] = None

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {"examples": [movie_update_schema_example]},
    }

    @field_validator("year")
    @classmethod
    def validate_year(cls, value: Optional[int]) -> Optional[int]:
        if value is None:
            return value
        current_year = datetime.now().year
        if value > current_year + 1:
            raise ValueError(f"Year cannot be greater than {current_year + 1}.")
        return value


class MovieListItemSchema(BaseModel):
    id: int
    uuid: UUID
    name: str
    year: int
    time: int
    imdb: float

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {"examples": [movie_item_schema_example]},
    }


class MovieDetailSchema(MovieBaseSchema):
    id: int
    uuid: UUID
    certification: CertificationSchema
    genres: list[GenreSchema]
    stars: list[StarSchema]
    directors: list[DirectorSchema]

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {"examples": [movie_detail_schema_example]},
    }


class MovieListResponseSchema(BaseModel):
    movies: list[MovieListItemSchema]
    prev_page: Optional[str]
    next_page: Optional[str]
    total_pages: int
    total_items: int

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {"examples": [movie_list_response_schema_example]},
    }
