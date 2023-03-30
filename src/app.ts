import express from 'express';
import morgan from 'morgan';
import helmet from 'helmet';
import cors from 'cors';
import compression from 'compression';
import mongoSanitize from 'express-mongo-sanitize';
import rateLimit from 'express-rate-limit';

const app = express();
const port = process.env.PORT || 5000;

// middleware for production
if (process.env.NODE_ENV === 'production') {
  app.use(helmet()); // helps secure Express app by setting various HTTP headers
  app.use(cors()); // enables Cross-Origin Resource Sharing
  app.use(compression()); // compresses the response bodies
  app.use(mongoSanitize()); // removes potentially malicious MongoDB operator symbols from req.query, req.params and req.body
  app.use(rateLimit({ // limits the number of requests per IP address
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // limit each IP to 100 requests per windowMs
  }));
}

// middleware for development
if (process.env.NODE_ENV === 'development') {
  app.use(morgan('dev')); // logs HTTP requests to the console
}

// default route
app.get('/', (req, res) => {
  res.send('Hello, World!');
});

// start the server
app.listen(port, () => {
  console.log(`Server listening on port ${port}`);
});
