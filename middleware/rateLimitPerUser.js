const userRateMap = {};

module.exports = function perUserRateLimit(req, res, next) {
  const id = req.session?.user?.id;
  if (!id) return res.status(401).json({ message: "Not logged in" });

  if (!userRateMap[id]) userRateMap[id] = [];

  const now = Date.now();
  userRateMap[id] = userRateMap[id].filter(t => now - t < 60000);

  if (userRateMap[id].length > 20) {
    return res.status(429).json({
  message: "Max requests reached. Try again in 1 minute."
});}

  userRateMap[id].push(now);
  next();
};