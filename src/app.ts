import cookieParser from "cookie-parser";
import cors from "cors";
import express, {
	type Application,
	NextFunction,
	type Request,
	type Response,
} from "express";
import httpStatus from "http-status";
import config from "./app/config";
import { redisClient } from "./app/lib/redis";
import { globalErrorHandler } from "./app/middleware/globalErrorHandler";
import { notFound } from "./app/middleware/notFound";
import { AuthRoutes } from "./app/module/auth/auth.route";

const app: Application = express();

app.use(
	cors({
		origin: config.frontend_url,
		credentials: true,
	}),
);

// Enable URL-encoded form data parsing
app.use(express.urlencoded({ extended: true }));

// Middleware to parse JSON bodies
app.use(express.json());
app.use(cookieParser());

app.use("/api/v1/auth", AuthRoutes);

// app.get("/redis", async (_req: Request, res: Response, next: NextFunction) => {
//   try {
//     await redisClient.set("forgot-password-otp:patient1@gmail.com", "123456", {
//       expiration: {
//         type: "EX",
//         value: 60,
//       },
//     });

//     res.status(httpStatus.OK).json({
//       success: true,
//       message: "OTP set successfully in Redis",
//     });
//   } catch (error) {
//     next(error);
//   }
// });

// Basic route
app.get("/", async (_req: Request, res: Response) => {
	res.status(httpStatus.OK).json({
		success: true,
		message: "Welcome to Healthcare System Backend",
	});
});

app.use(globalErrorHandler);
app.use(notFound);

export default app;
