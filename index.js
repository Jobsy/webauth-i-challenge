const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const KnexSessionStore = require('connect-session-knex')(session);


const db = require('./data/dbConfig.js');
const Users = require('./users/users-model.js');

const server = express();

const sessionConfig = {
  name: 'myFirstCookieSession',
  secret: 'make it a little long and keep it safe!',
  cookie: {
    maxAge: 1000 * 60 * 60,
    secure: false, 
    httpOnly: false,
  },
  resave: false,
  saveUninitialized: false,
  store: new KnexSessionStore({
    knex: require('../database/dbConfig'),
    tablename: 'sessions',
    sidfieldname: 'sid',
    createtable: true,
    clearInterval: 1000 * 60 * 60
  })
}

server.use(helmet());
server.use(express.json());
server.use(cors());

server.get('/', (req, res) => {
  res.send("It's alive!");
});

server.get('/logout', (req, res) => {
  if (req.session) {
    req.session.destroy(err => {
      if (err) {
        res.json('you can not leave, actually')
      } else {
        res.json('goodbye, sad to see you go')
      }
    })
  } else {
    res.end();
  }
})

server.post('/api/register', (req, res) => {
  let user = req.body;
  const hash = bcrypt.hashSync(user.password, 11)
  const user1 = {
    username: req.body.username,
    password: hash,
  }

  Users.add(user1)
    .then(saved => {
      res.status(201).json(saved);
    })
    .catch(error => {
      res.status(500).json("error while loging in: " + error);
    });
});

server.post('/api/login', (req, res) => {
  let { username, password } = req.body;

  Users.findBy({ username })
    .first()
    .then(user => {
      if (user && bcrypt.compareSync(password, user.password)) {
        req.session.user = user;
        res.status(200).json({ message: `Welcome ${user.username}!` });
      } else {
        res.status(401).json({ message: 'Invalid Credentials' });
      }
    })
    .catch(error => {
      res.status(500).json({ message: error.message });
    });
});

// function restricted(req, res, next) {
//   const { username, password } = req.headers
//   Users.findBy({ username })
//     .first()
//     .then(user => {
//       if (user && bcrypt.compareSync(password, user.password)) {
//         next()
//       } else {
//         res.status(401).json({ message: 'Invalid Credentials' });
//       }
//     })
//     .catch(error => {
//       res.status(500).json({ message: error.message });
//     });
// }

function restricted(req, res, next) {
  if (req.session && req.session.user) {
    next();
  } else {
    res.status(400).json({ message: 'No credentials provided' });
  }
};


server.get('/api/users', restricted, (req, res) => {
  Users.find()
    .then(users => {
      res.json(users);
    })
    .catch(err => res.send(err));
});

const port = process.env.PORT || 5000;
server.listen(port, () => console.log(`\n** Running on port ${port} **\n`));
