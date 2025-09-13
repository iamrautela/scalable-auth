const redis = require('redis');

const redisClient = redis.createClient({
  host: process.env.REDIS_HOST || 'localhost',
  port: process.env.REDIS_PORT || 6379,
  ...(process.env.REDIS_PASSWORD && { password: process.env.REDIS_PASSWORD })
});

redisClient.on('connect', () => {
  console.log('Connected to Redis');
});

redisClient.on('error', (err) => {
  console.error('Redis connection error:', err);
});

// Handle process termination
process.on('SIGINT', () => {
  redisClient.quit();
  process.exit(0);
});

module.exports = redisClient;