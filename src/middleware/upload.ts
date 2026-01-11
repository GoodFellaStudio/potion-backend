import { GetObjectCommand, S3Client } from "@aws-sdk/client-s3";
import multer from "multer";
import multerS3 from "multer-s3";
import { config } from "../config/config";

const s3 = new S3Client({
  credentials: {
    accessKeyId: config.awsAccessKeyId,
    secretAccessKey: config.awsSecretAccessKey,
  },
  region: config.awsRegion,
});

const upload = multer({
  storage: multerS3({
    s3: s3,
    bucket: config.s3BucketName,
    acl: "private",
    metadata: (req, file, cb) => {
      cb(null, { fieldName: file.fieldname});
    },
    key: (req, file, cb) => {
      cb(null, `${Date.now()}-${file.originalname}`);
    },
  }),
  limits: {
    fileSize: 12 * 1024 * 1024
  }
});

export const uploadF = async (req: any, res: any, next: any) => {
  try {
    upload.array("profilePicture")(req, res, async (err: any) => {
      if (err) {
        console.log(">>>1", err, err?.message);
        if(err?.message?.includes("too large")){
          return res.status(500).json({ error: err?.message});
        }
        return res.status(500).json({ error: "Failed to upload files" });
      }

      const files = req.files;

      if (!files || files.length === 0) {
        console.log(">>>2", "not files");
        return res.status(400).json({ error: "No files uploaded" });
      }

      const uploadedFiles = await Promise.all(
        files.map(async (file: any) => {
          return {
            fileDisplayName: file.originalname,
            fileName: file.key,
            fileType: file.mimetype,
            uploadDate: Date.now(),
            status: "Created",
          };
        })
      );

      req.filesInfo = uploadedFiles;

      next();
    });
  } catch (error) {
    console.log(error);
    throw error;
  }
};

export const directDownload = async (req: any, res: any) => {
  const { fileName } = req.params;
  
  try {
    const command = new GetObjectCommand({
      Bucket: config.s3BucketName,
      Key: fileName,
    });

    const { Body, ContentType } = await s3.send(command);
    res.setHeader('Content-Type', ContentType);
    res.setHeader('Content-Disposition', `attachment; filename="${fileName}"`);
    
    // Stream the file directly from S3 to client
    (Body as NodeJS.ReadableStream).pipe(res);
  } catch (error) {
    console.error("Download error:", error);
    res.status(404).json({ error: "File not found" });
  }
};

export default upload;
