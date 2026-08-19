from database import MovieModel

ALLOWED_SORT_FIELDS = {
    "name": MovieModel.name,
    "year": MovieModel.year,
    "time": MovieModel.time,
    "imdb": MovieModel.imdb,
    "votes": MovieModel.votes,
    "meta_score": MovieModel.meta_score,
    "gross": MovieModel.gross,
    "price": MovieModel.price,
}
