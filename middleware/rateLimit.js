const redis = require('redis');
const { RateLimiterRedis } = require('rate-limiter-flexible');
const redisClient = require('../config/redis');

// Rate limiter for general endpoints
const generalRateLimiter = new RateLimiterRedis({
  storeClient: redisClient,
  keyPrefix: 'middleware',
  points: 10, // 10 requests
  duration: 1, // per 1 second
  blockDuration: 60, // block for 60 seconds if exceeded
});

// Rate limiter for authentication endpoints (more strict)
const authRateLimiter = new RateLimiterRedis({
  storeClient: redisClient,
  keyPrefix: 'auth',
  points: 5, // 5 requests
  duration: 1, // per 1 second
  blockDuration: 300, // block for 5 minutes if exceeded
});

const rateLimit = (limiter) => async (req, res, next) => {
  try {
    await limiter.consume(req.ip);
    next();
  } catch (rejRes) {
    res.status(429).json({ error: 'Too many requests' });
  }
};

module.exports = {
  generalRateLimit: rateLimit(generalRateLimiter),
  authRateLimit: rateLimit(authRateLimiter)
};