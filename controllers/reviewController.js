const Review = require('./../models/reviewModel');
const handlerFactory = require('./handlerFactory');

exports.setTourUserIds = (req, res, next) => {
  req.body.tour ||= req.params.tourId;
  req.body.user ||= req.user.id;

  next();
};

exports.getReviews = handlerFactory.getAll(Review);
exports.getReview = handlerFactory.getOne(Review);
exports.createReview = handlerFactory.createOne(Review);
exports.updateReview = handlerFactory.updateOne(Review);
exports.deleteReview = handlerFactory.deleteOne(Review);
