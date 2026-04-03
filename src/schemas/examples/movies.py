movie_item_schema_example = {
    "id": 9933,
    "uuid": "0f8fad5b-d9cb-469f-a165-70867728950e",
    "name": "The Swan Princess: A Royal Wedding",
    "year": 2020,
    "time": 83,
    "imdb": 6.4,
}

movie_list_response_schema_example = {
    "movies": [movie_item_schema_example],
    "prev_page": "/theater/movies/?page=1&per_page=1",
    "next_page": "/theater/movies/?page=3&per_page=1",
    "total_pages": 9933,
    "total_items": 9933,
}

movie_create_schema_example = {
    "name": "New Movie",
    "year": 2025,
    "time": 126,
    "imdb": 8.5,
    "votes": 125000,
    "meta_score": 77.0,
    "gross": 154000000.0,
    "description": "An amazing movie.",
    "price": "19.99",
    "certification_id": 2,
    "genre_ids": [1, 2],
    "star_ids": [3, 4],
    "director_ids": [5],
}


star_schema_example = {
    "id": 1,
    "name": "Chris Evans",
}

certification_schema_example = {
    "id": 1,
    "name": "PG-13",
}

genre_schema_example = {
    "id": 1,
    "name": "Comedy",
}

director_schema_example = {
    "id": 1,
    "name": "Christopher Nolan",
}

movie_detail_schema_example = {
    **movie_item_schema_example,
    "votes": 125000,
    "meta_score": 77.0,
    "gross": 154000000.0,
    "description": "An amazing movie.",
    "price": "19.99",
    "certification_id": 2,
    "certification": certification_schema_example,
    "genres": [genre_schema_example],
    "stars": [star_schema_example],
    "directors": [director_schema_example],
}

movie_update_schema_example = {
    "name": "Update Movie",
    "year": 2026,
    "imdb": 8.7,
    "meta_score": 80.0,
    "description": "Updated movie description.",
    "price": "17.99",
    "genre_ids": [1],
}
