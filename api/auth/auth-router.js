const router = require("express").Router();
const jwt = require("jsonwebtoken")
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const { JWT_SECRET } = require("../secrets"); // use this secret!
const { add } = require('../users/users-model');
const bcrypt = require('bcryptjs');

router.post("/register", validateRoleName, async (req, res, next) => {
  try {
    const { username, password } = req.body;
    const { role_name } = req
    const hash = bcrypt.hashSync(password, 4)
    req.body.password = hash
    const newUser = await add({ username: username, password: hash, role_name: role_name })
    res.status(201).json(newUser)
  } catch (error) {
    next(error);
  }

  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */
});


router.post("/login", checkUsernameExists, (req, res, next) => {
  try {
    if (req.user && bcrypt.compareSync(req.body.password, req.user.password)) {

      const token = buildToken(req.user)
      res.status(200).json({
        message: `${req.user.username} is back!`,
        token: token
      })
    } else {
      next({ status: 401, message: 'Invalid credentials' })
    }
  } catch (error) {
    next(error);
  }
  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */
});

function buildToken(user) {
  const payload = {
    subject: user.user_id,
    username: user.username,      // what we see on our payload
    role_name: user.role_name,
  }
  const options = {
    expiresIn: '1d'
  }
  return jwt.sign(
    payload,
    JWT_SECRET,
    options,
  )


}

module.exports = router;
