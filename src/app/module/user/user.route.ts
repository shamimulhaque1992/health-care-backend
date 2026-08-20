import { Router } from "express";
import { userController } from "./users.controller";
import { upload } from "../../lib/multer";
import { auth } from "../../middleware/checkAuth";
import { Role } from "../../../generated/prisma/enums";

const router = Router();

router.patch(
	"/profile-image",
	auth(Role.SUPER_ADMIN, Role.ADMIN, Role.DOCTOR, Role.PATIENT),
	upload.single("profileImage"),
	userController.uploadImage,
);

export const UserRoutes = router;
