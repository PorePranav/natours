const express = require('express');
const viewsController = require('./../controllers/viewsController');
const router = express.Router();
const authController = require('./../controllers/authController');

router.use(authController.isLoggedIn);

router.get('/', viewsController.getOverview);
router.get('/tour/:slug', viewsController.getTour);
router.get('/login', viewsController.login);
router.get('/signup', viewsController.signup);

module.exports = router;
