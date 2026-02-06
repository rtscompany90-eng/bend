require('dotenv').config();
const express = require('express');
const fileUpload = require('express-fileupload');
const cloudinary = require('cloudinary').v2;
const axios = require('axios');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const helmet = require('helmet');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;
const DB_FILE = path.join(__dirname, 'database.json');
const UPLOAD_DIR = path.join(__dirname, 'uploads');

// Cloudinary Configuration
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

// Ensure database file exists
if (!fs.existsSync(DB_FILE)) {
    fs.writeFileSync(DB_FILE, JSON.stringify([]));
}

// Middleware
app.use(helmet());
app.use(cors()); // Allow all origins by default for easy frontend integration
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(fileUpload({
    useTempFiles: true,
    tempFileDir: path.join(__dirname, 'tmp')
}));

// Database Helpers
const readDb = () => {
    try {
        const data = fs.readFileSync(DB_FILE, 'utf8');
        return JSON.parse(data);
    } catch (err) {
        return [];
    }
};

const writeDb = (data) => {
    fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
};

// Multer and local storage removed in favor of Cloudinary

// ================= API ROUTES =================

// 1. GET /api/files - List all secured files (Public Metadata only)
app.get('/api/files', (req, res) => {
    const files = readDb().sort((a, b) => b.timestamp - a.timestamp); // Newest first
    const safeFiles = files.map(file => ({
        id: file.id,
        originalName: file.originalName,
        mimeType: file.mimeType,
        size: file.size,
        timestamp: file.timestamp,
        isProtected: true // Just a flag for UI
    }));
    res.json(safeFiles);
});

// 2. POST /api/upload - Upload a file with password
app.post('/api/upload', async (req, res) => {
    console.log("Upload request received");

    if (!req.files || Object.keys(req.files).length === 0 || !req.body.password) {
        return res.status(400).json({ error: 'File and password are required.' });
    }

    const file = req.files.file;
    const password = req.body.password;

    try {
        console.log("Hashing password...");
        const hashedPassword = await bcrypt.hash(password, 10);

        console.log("Uploading to Cloudinary...");
        const uploadResult = await cloudinary.uploader.upload(file.tempFilePath, {
            folder: 'rts_uploads',
            resource_type: 'auto'
        });

        const newFile = {
            id: uuidv4(),
            originalName: file.name,
            cloudId: uploadResult.public_id,
            url: uploadResult.secure_url,
            resourceType: uploadResult.resource_type || 'auto',
            mimeType: file.mimetype || 'application/octet-stream',
            size: file.size,
            password: hashedPassword,
            timestamp: Date.now()
        };

        const db = readDb();
        db.push(newFile);
        writeDb(db);

        console.log(`File saved to DB. ID: ${newFile.id}, Type: ${newFile.resourceType}`);
        res.status(201).json({
            message: 'File uploaded and protected.',
            fileId: newFile.id
        });
    } catch (err) {
        console.error("Upload process error:", err);
        res.status(500).json({ error: 'Server Error during upload: ' + err.message });
    }
});

// 3. POST /api/files/:id/download - Verify password and Get URL (Supports both singular and plural)
app.post(['/api/file/:id/download', '/api/files/:id/download'], async (req, res) => {
    const { id } = req.params;
    const { password } = req.body;

    console.log(`Download attempt for file ID: ${id}`);

    if (!password) {
        return res.status(400).json({ error: 'Password is required.' });
    }

    const db = readDb();
    const file = db.find(f => f.id === id);

    if (!file) {
        console.error(`File not found in DB: ${id}`);
        return res.status(404).json({ error: 'File not found.' });
    }

    try {
        console.log(`Verifying password for: ${file.originalName}`);
        const isMatch = await bcrypt.compare(password, file.password);

        if (isMatch) {
            console.log("Password verified. Starting stream...");

            // For files that might have been uploaded before the resourceType change
            const resourceType = file.resourceType || 'auto';
            const fileUrl = file.url;

            if (!fileUrl) {
                console.error("No URL found for file in DB");
                return res.status(500).json({ error: "File URL missing in database." });
            }

            const response = await axios({
                method: 'get',
                url: fileUrl,
                responseType: 'stream',
                timeout: 30000 // 30 second timeout for Cloudinary fetch
            });

            res.setHeader('Content-Type', file.mimeType);
            res.setHeader('Content-Disposition', `attachment; filename="${file.originalName}"`);

            response.data.pipe(res);

            response.data.on('error', (err) => {
                console.error("Stream error:", err);
                if (!res.headersSent) {
                    res.status(500).send("Error streaming file.");
                }
            });

        } else {
            console.warn(`Invalid password for file: ${file.originalName}`);
            res.status(401).json({ error: 'Incorrect password. Access denied.' });
        }
    } catch (err) {
        console.error("Download process error:", err);
        res.status(500).json({ error: 'Internal processing error: ' + err.message });
    }
});

// 4. DELETE /api/files/:id - Remove file from Cloudinary and metadata (Supports both singular and plural)
app.delete(['/api/file/:id', '/api/files/:id'], async (req, res) => {
    const { id } = req.params;
    const db = readDb();
    const fileIndex = db.findIndex(f => f.id === id);

    if (fileIndex === -1) {
        return res.status(404).json({ error: 'File not found.' });
    }

    const file = db[fileIndex];

    try {
        // Delete from Cloudinary
        if (file.cloudId) {
            await cloudinary.uploader.destroy(file.cloudId);
        }

        // Delete from DB
        db.splice(fileIndex, 1);
        writeDb(db);

        res.json({ message: 'File deleted successfully from Cloudinary and database.' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to delete file: ' + err.message });
    }
});

// Global Error Handler
app.use((err, req, res, next) => {
    console.error("Global error handler:", err);
    return res.status(500).json({ error: err.message || 'Internal Server Error' });
});

// Start Server
app.listen(PORT, () => {
    console.log(`Backend API Server running on http://localhost:${PORT}`);
    console.log(`- Storage: Cloudinary`);
    console.log(`- API Ready: GET /api/files | POST /api/upload | POST /api/file/:id/download`);
});
