import { NextFunction, Request, Response } from "express";
import { catchAsync } from "../../utils/catchAsync";
import { sendResponse } from "../../utils/sendResponse";
import httpStatus from "http-status";
import { userServices } from "./users.service";

const uploadImage = catchAsync(
	async (req: Request, res: Response, next: NextFunction) => {
		const file = req.file?.buffer;
		const userId = req.user?.userId as string;

		if (!file) {
			throw new Error("No file uploaded");
		}

		const result = await userServices.uploadImage(file, userId);

		sendResponse(res, {
			success: true,
			statusCode: httpStatus.OK,
			message: "Profile image uploaded successfully",
			data: result,
		});
	},
);

export const userController = {
	uploadImage,
};
