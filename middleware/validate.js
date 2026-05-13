const { z } = require("zod");

// 🔐 Strong password rules
const passwordSchema = z
  .string()
  .min(8, "Password must be at least 8 characters long")
  .max(100, "Password is too long")
  .regex(/^(?=.*[A-Za-z])(?=.*\d).{8,}$/, 
    "Password must contain letters and numbers");

// 👤 Register schema (NO email since your frontend doesn't use it)
const registerSchema = z.object({
  username: z
  .string()
  .min(6, "Username must be at least 6 characters")
  .max(20, "Username must be less than 20 characters")
  .regex(/^(?=.*\d)[a-zA-Z0-9_]+$/, 
    "Username must contain at least one number"),

  password: passwordSchema
});

// 🛡️ Middleware
function validateRegister(req, res, next) {
  const result = registerSchema.safeParse(req.body);

  if (!result.success) {
    const errors = result.error.issues.map((e) => e.message);

    return res.status(400).json({
      message: "Weak or invalid input",
      errors
    });
  }

  next();
}

module.exports = { validateRegister };