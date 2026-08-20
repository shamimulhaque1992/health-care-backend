import { cloudinary } from "../../lib/cloudinary";

const uploadImage = async (buffer: Buffer, userId: string) => {
	cloudinary.uploader
		.upload_stream({ resource_type: "auto" }, (error, result) => {
			if (error) {
				console.error(`Cloudinary upload failed: ${error.message}`);
				throw new Error(`Cloudinary upload failed: ${error.message}`);
			}
		})
		.end(buffer);
};

export const userServices = {
	uploadImage,
};
