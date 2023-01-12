import express, { NextFunction, Request, Response } from 'express';
import dotenv from 'dotenv';
import cors from 'cors';
import { MongoClient, Db, ObjectId, MongoServerError } from 'mongodb';
import { initializeApp } from "firebase/app";
import { getStorage, ref, uploadBytes, getDownloadURL } from "firebase/storage";
import multer from "multer";
import path from "path";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

dotenv.config();
const app = express();
const APP_PORT = 5000;
app.use(cors({ origin: true }));
app.use(express.json());

if (!process.env.FIREBASE_API_KEY) {
    console.warn("Please add FIREBASE_API_KEY to the .env.")
}
const firebaseConfig = {
    apiKey: process.env.FIREBASE_API_KEY,
    authDomain: process.env.FIREBASE_AUTH_DOMAIN,
    projectId: process.env.FIREBASE_PROJECT_ID,
    storageBucket: process.env.FIREBASE_STORAGE_BUCKET,
    messagingSenderId: process.env.FIREBASE_MESSAGING_SENDER_ID,
    appId: process.env.FIREBASE_APP_ID
};
const firebaseApp = initializeApp(firebaseConfig);
const storage = getStorage(firebaseApp);
const uploader = multer({
    storage: multer.memoryStorage(),
    limits: {
        fileSize: 5 * 1024 * 1024, // keep file size < 5 KB
    },
});

if (!process.env.DATABASE_URI) {
    console.warn("Please add DATABASE_URI to the .env.")
}
const mongoClient = new MongoClient(process.env.DATABASE_URI as string);

interface UserSchema {
    _id: ObjectId // user's ID
    firstName: string // user's first name
    lastName: string // user's last name
    email: string // user's email
    password: string // user's password used only in level 3 and beyond
    profilePicture?: string | null // pointer to user's profile picture in cloud storage --> used in Expert level
};

interface AnimalSchema {
    _id: ObjectId // animal's ID
    name: string // animal's name
    hoursTrained: number // total number of hours the animal has been trained for
    owner: ObjectId // id of the animal's owner
    dateOfBirth?: Date | null // animal's date of birth
    profilePicture?: string | null // pointer to animal's profile picture in cloud storage --> used in Expert level
}

interface TrainingLogSchema {
    _id: ObjectId // training log's id
    date: Date // date of training log
    description: string // description of training log
    hours: number // number of hours the training log records
    animal: ObjectId // animal this training log corresponds to
    user: ObjectId // user this training log corresponds to
    trainingLogVideo?: string | null // pointer to training log video in cloud storage --> used in Expert level
}

interface FileUploadData {
    ext: string
    type: string
    name: string
}

interface FileUploadInfo {
    data?: FileUploadData
    name?: string
    owner?: ObjectId
}

type AuthenticatedRequest = Request & {
    user?: UserSchema
}

type FileUploadRequest = AuthenticatedRequest & {
    fileUpload?: FileUploadInfo
}

interface ValidUploadTypes {
    animalProfilePicture: {
        field: string
        collection: string
    }
    userProfilePicture: {
        field: string
        collection: string
    }
    trainingLogVideo: {
        field: string
        collection: string
    }
}

class DoesNotExistError extends Error {
    collection: string

    constructor(message: string, collection: string) {
        super(message);
        this.collection = collection;
    }
}

class AlreadyExistsError extends Error {
    collection: string

    constructor(message: string, collection: string) {
        super(message);
        this.collection = collection;
    }
}

class UserAlreadyExistsError extends AlreadyExistsError {
    user: UserSchema

    constructor(message: string, user: UserSchema) {
        super(message, "users");
        this.user = user;
    }
}

class AnimalOwnerUserMismatchError extends Error {
    animal: ObjectId
    owner: ObjectId
    user?: ObjectId

    constructor(message: string, animal: ObjectId, owner: ObjectId, user: ObjectId | undefined) {
        super(message);
        this.animal = animal;
        this.owner = owner;
        this.user = user;
    }
}

function authenticateToken(req: AuthenticatedRequest, res: Response, next: NextFunction) {
    const authHeader = req.headers['authorization'];
    const token = authHeader?.split(' ')[1];
    if (token == null) {
        return res.sendStatus(401);
    }
    if (!process.env.JWT_STRING) {
        console.warn("Please add JWT_STRING to the .env.");
    }
    jwt.verify(token, process.env.JWT_STRING as string, (err: any, user: any) => {
        if (err) {
            return res.sendStatus(403);
        } 
        if (typeof user._id === "string") {
            user._id = new ObjectId(user._id);
        }
        req.user = user;
        next();
    });
}

function processUpload(req: FileUploadRequest, res: Response, next: NextFunction) {
    const fileUpload = uploader.single("file");
    const videoTypes = [".mov", ".mp4"];
    const imageTypes = [".png", ".jpg", ".gif", ".webp", ".heif", ".jpeg"];
    fileUpload(req, res, async (err) => {
        if (err instanceof multer.MulterError) {
            console.error(`Error in Multer processing: ${JSON.stringify(err as multer.MulterError)}`);
            res.status(500).send();
            return;
        }
        if (req.file) {
            const fileExt = path.extname(req.file.originalname)
            if (!videoTypes.includes(fileExt) && !imageTypes.includes(fileExt)) {
                res.status(400).send("Invalid upload type.");
                return;
            }
            const type = videoTypes.includes(fileExt) ? "video" : "image";
            req.fileUpload = {
                "data": {
                    "ext": fileExt, 
                    "type": type, 
                    "name": req.file.originalname
                },
                "owner": req.user?._id, 
                "name": req.file.originalname
            };
        } else {
            res.status(400).send("File not provided.");
            return;
        }
        next();
    });
}

class DBConnection {
    dbName: string
    connection?: any
    db?: Db

    constructor(dbName: string) {
        this.connection = null;
        this.dbName = dbName; // "spring23-dev-assessment"
        this.getDb();
    }

    async connect(): Promise<Db> {
        try {
            this.connection = await mongoClient.connect();
        } catch (err: unknown) {
            console.error("Failed to connect to database.");
            return Promise.reject(err);
        }
        return mongoClient.db(this.dbName);
    };

    async getDb(): Promise<Db> {
        if (!this.db) {
            this.db = await this.connect();
        }
        return this.db;
    };

    async documentWithIdExists(id: ObjectId | string, collectionName: string): Promise<boolean> {
        if (typeof id === "string") {
            id = new ObjectId(id);
        }
        let collection = this.db?.collection(collectionName);
        if (!collection) {
            return false;
        }
        let item = await collection.findOne( {_id: id} );
        return item !== null && item !== undefined;
    }

    async createAnimalCollection(): Promise<Error | undefined> {
        try {
            await this.db?.createCollection("animals", {
                validator: {
                    $jsonSchema: {
                        bsonType: "object",
                        title: "Animal Object Validation",
                        additionalProperties: false,
                        required: [ "_id", "name", "hoursTrained", "owner", "dateOfBirth", "profilePicture" ],
                        properties: {
                            _id: {
                                bsonType: "objectId",
                                description: "'_id' must be an ObjectID and is required"
                            },
                            name: {
                                bsonType: "string",
                                description: "'name' must be a string and is required"
                            },
                            hoursTrained: {
                                bsonType: "number",
                                description: "'hoursTrained' must be a number and is required"
                            },
                            owner: {
                                bsonType: "objectId",
                                description: "'owner' must be an ObjectID and is required"
                            },
                            dateOfBirth: {
                                bsonType: ["date", "null"],
                                description: "'dateOfBirth' must be a date or null and is required"
                            },
                            profilePicture: {
                                bsonType: ["string", "null"],
                                description: "'profilePicture' must be a string or null and is required"
                            },
                        },
                    }
                }
            });
        } catch (err) {
            return err as Error;
        }
    };

    async createUserCollection(): Promise<Error | undefined> {
        try {
            await this.db?.createCollection("users", {
                validator: {
                    $jsonSchema: {
                        bsonType: "object",
                        title: "User Object Validation",
                        required: [ "_id", "firstName", "lastName", "email", "password", "profilePicture" ],
                        additionalProperties: false,
                        properties: {
                            _id: {
                                bsonType: "objectId",
                                description: "'_id' must be an ObjectID and is required"
                            },
                            firstName: {
                                bsonType: "string",
                                description: "'firstName' must be a string and is required"
                            },
                            lastName: {
                                bsonType: "string",
                                description: "'lastName' must be a string and is required"
                            },
                            email: {
                                bsonType: "string",
                                description: "'email' must be a string and is required"
                            },
                            password: {
                                bsonType: "string",
                                description: "'password' must be a string and is required"
                            },
                            profilePicture: {
                                bsonType: ["string", "null"],
                                description: "'profilePicture' must be a string or null and is required"
                            },
                        },
                    }
                }
            });
        } catch (err) {
            return err as Error;
        }
    };

    async createTrainingLogCollection(): Promise<Error | undefined> {
        try {
            await this.db?.createCollection("trainingLogs", {
                validator: {
                    $jsonSchema: {
                        bsonType: "object",
                        title: "Training Log Object Validation",
                        additionalProperties: false,
                        required: [ "_id", "date", "description", "hours", "animal", "user", "trainingLogVideo" ],
                        properties: {
                            _id: {
                                bsonType: "objectId",
                                description: "'_id' must be an ObjectID and is required"
                            },
                            date: {
                                bsonType: "date",
                                description: "'date' must be a date and is required"
                            },
                            hours: {
                                bsonType: "number",
                                description: "'hours' must be a number and is required"
                            },
                            description: {
                                bsonType: "string",
                                description: "'description' must be a string and is required"
                            },
                            animal: {
                                bsonType: "objectId",
                                description: "'animal' must be an ObjectID and is required"
                            },
                            user: {
                                bsonType: "objectId",
                                description: "'user' must be a ObjectID and is required"
                            },
                            trainingLogVideo: {
                                bsonType: ["string", "null"],
                                description: "'trainingLogVideo' must be a string or null and is required"
                            },
                        },
                    }
                }
            });
        } catch (err) {
            return err as Error;
        }
    };

    async addUser(user: UserSchema): Promise<Error | boolean> {
        try {
            const created = await this.createUserCollection(); // doesn't actually run if collection already exists
            if (typeof created !== "undefined") {
                if (created.name == "MongoServerError") {
                    const serverErr = created as MongoServerError;
                    if (serverErr.codeName !== "NamespaceExists") {
                        return created;
                    }
                }
            }
            const users = this.db?.collection("users");
            const alreadyExists = await users?.findOne({ email: user.email });
            if (alreadyExists) {
                throw new UserAlreadyExistsError("User already exists with this email.", user);
            }
            if (user.profilePicture == undefined) {
                user.profilePicture = null;
            }
            const passHash = await bcrypt.hash(user.password, 10);
            user.password = passHash;
            await users?.insertOne(user);
            return true;
        } catch (err) {
            return err as Error;
        }
    };

    async addAnimal(animal: AnimalSchema): Promise<Error | boolean> {
        try {
            const created = await this.createAnimalCollection(); // doesn't actually run if collection already exists
            if (typeof created !== "undefined") {
                if (created.name == "MongoServerError") {
                    const serverErr = created as MongoServerError;
                    if (serverErr.codeName !== "NamespaceExists") {
                        return created;
                    }
                }
            }
            const animals = this.db?.collection("animals");
            if (animal.profilePicture == undefined) {
                animal.profilePicture = null;
            }
            if (animal.dateOfBirth == undefined) {
                animal.dateOfBirth = null;
            }
            animal.owner = new ObjectId(animal.owner);
            await animals?.insertOne(animal);
            return true;
        } catch (err) {
            return err as Error;
        }
    };

    async addTrainingLog(log: TrainingLogSchema): Promise<Error | boolean> {
        try {
            const created = await this.createTrainingLogCollection(); // doesn't actually run if collection already exists
            if (typeof created !== "undefined") {
                if (created.name == "MongoServerError") {
                    const serverErr = created as MongoServerError;
                    if (serverErr.codeName !== "NamespaceExists") {
                        return created;
                    }
                }
            }
            const logs = this.db?.collection("trainingLogs");
            if (log.trainingLogVideo == undefined) {
                log.trainingLogVideo = null;
            }
            log.date = new Date(log.date);
            log.animal = new ObjectId(log.animal);
            log.user = new ObjectId(log.user);
            const animal = await this.getAnimalById(log.animal);
            const user = await this.getUserById(log.user);
            if (!animal) {
                throw new DoesNotExistError("Provided animal does not exist.", "animals");
            } else if (!user) {
                throw new DoesNotExistError("Provided user does not exist.", "users");
            }
            if (animal?.owner.toString() !== log.user.toString()) {
                throw new AnimalOwnerUserMismatchError("The provided animal's owner is not the same as the provided user.", 
                    log.animal, animal?.owner, log.user);
            }
            await logs?.insertOne(log);
            return true;
        } catch (err) {
            return err as Error;
        }
    };

    async getUserById(id: ObjectId | string): Promise<UserSchema> {
        if (typeof id === "string") {
            id = new ObjectId(id);
        }
        const users = this.db?.collection("users");
        const user = await users?.findOne({_id: id});
        if (!user) throw new DoesNotExistError(`User with id ${id} does not exist.`, "users"); 
        return user as UserSchema;
    }

    async getUserByEmail(email: string): Promise<UserSchema> {
        const users = this.db?.collection("users");
        const user = await users?.findOne({email: email});
        if (!user) throw new DoesNotExistError(`User with email ${email} does not exist.`, "users"); 
        return user as UserSchema;
    }

    async getUsers(pageSize: number = 5, pageNum: number = 1): Promise<Array<UserSchema>> {
        const users = this.db?.collection("users");
        const allUsers = users?.find().project({"password": 0}).skip(pageSize * (pageNum - 1)).limit(pageSize);
        return await allUsers?.toArray() as Array<UserSchema>;
    }

    async updateUserById(id: ObjectId | string, values: object): Promise<boolean> {
        if (typeof id === "string") {
            id = new ObjectId(id);
        }
        const users = this.db?.collection("users");
        const user = await users?.updateOne({_id: id}, {$set: values});
        if (user?.matchedCount == 0) throw new DoesNotExistError(`User with id ${id} does not exist.`, "users"); 
        return user?.modifiedCount === 1;
    }

    async getAnimalById(id: ObjectId | string): Promise<AnimalSchema> {
        if (typeof id === "string") {
            id = new ObjectId(id);
        }
        const animals = this.db?.collection("animals");
        const animal = await animals?.findOne({_id: id});
        if (!animal) throw new DoesNotExistError(`Animal with id ${id} does not exist.`, "animals"); 
        return animal as AnimalSchema;
    }

    async getAnimals(pageSize: number = 5, pageNum: number = 1): Promise<Array<AnimalSchema>> {
        const animals = this.db?.collection("animals");
        const allAnimals = animals?.find().skip(pageSize * (pageNum - 1)).limit(pageSize);
        return await allAnimals?.toArray() as Array<AnimalSchema>;
    }

    async updateAnimalById(id: ObjectId | string, values: object): Promise<boolean> {
        if (typeof id === "string") {
            id = new ObjectId(id);
        }
        const animals = this.db?.collection("animals");
        const animal = await animals?.updateOne({_id: id}, {$set: values});
        if (animal?.matchedCount == 0) throw new DoesNotExistError(`Animal with id ${id} does not exist.`, "animals");
        return animal?.modifiedCount === 1;
    }

    async getTrainingLogById(id: ObjectId | string): Promise<TrainingLogSchema> {
        if (typeof id === "string") {
            id = new ObjectId(id);
        }
        const logs = this.db?.collection("trainingLogs");
        const log = await logs?.findOne({_id: id});
        if (!log) throw new DoesNotExistError(`Training Log with id ${id} does not exist.`, "trainingLogs"); 
        return log as TrainingLogSchema;
    }

    async getTrainingLogs(pageSize: number = 5, pageNum: number = 1): Promise<Array<TrainingLogSchema>> {
        const logs = this.db?.collection("trainingLogs");
        const allLogs = logs?.find().skip(pageSize * (pageNum - 1)).limit(pageSize);
        return await allLogs?.toArray() as Array<TrainingLogSchema>;
    }

    async updateTrainingLogById(id: ObjectId | string, values: object): Promise<boolean> {
        if (typeof id === "string") {
            id = new ObjectId(id);
        }
        const logs = this.db?.collection("trainingLogs");
        const log = await logs?.updateOne({_id: id}, {$set: values});
        if (log?.matchedCount == 0) throw new DoesNotExistError(`Training log with id ${id} does not exist.`, "trainingLogs");
        return log?.modifiedCount === 1;
    }
};

let _db = new DBConnection("spring23-dev-assessment");

app.get('/', authenticateToken, (req: AuthenticatedRequest, res: Response) => {
    res.json({"Hello": "World",
            "Version": 2});
});

app.get('/api/health', authenticateToken, async (req: AuthenticatedRequest, res: Response) => {
    res.json({"healthy": true});
});

app.post('/api/user', async (req: Request, res: Response) => {
    try {
        const addedUserStatus = await _db.addUser(req.body);
        if (typeof addedUserStatus === "boolean") {
            if (!addedUserStatus) {
                res.status(500).send();
                return;
            }
        } else {
            const mongoError = addedUserStatus as Error;
            if (mongoError.message === "Document failed validation") {
                const mongoError = addedUserStatus as MongoServerError;
                res.status(400).send(`Provided user schema invalid: ${JSON.stringify(mongoError.errInfo?.details)}`);
                return;
            } else {
                res.status(500).send(`Error in User creation: ${mongoError.message}`);
                return;
            }
        }
    } catch (err) {
        res.status(500).send(`Error in User creation: ${(err as Error).message}`);
        return;
    }
    res.status(200).send();
});

app.post('/api/animal', authenticateToken, async (req: AuthenticatedRequest, res: Response) => {
    try {
        req.body.owner = !req.body.owner ? req.user?._id : req.body.owner;
        const addedAnimalStatus = await _db.addAnimal(req.body);
        if (typeof addedAnimalStatus === "boolean") {
            if (!addedAnimalStatus) {
                res.status(500).send();
                return;
            }
        } else {
            const mongoError = addedAnimalStatus as Error;
            if (mongoError.message === "Document failed validation") {
                const mongoError = addedAnimalStatus as MongoServerError;
                res.status(400).send(`Provided animal schema invalid: ${JSON.stringify(mongoError.errInfo?.details)}`);
                return;
            } else {
                res.status(500).send(`Error in Animal creation: ${mongoError.message}`);
                return;
            }
        }
    } catch (err) {
        res.status(500).send(`Error in Animal creation: ${(err as Error).message}`);
        return;
    }
    res.status(200).send();
});

app.post('/api/training', authenticateToken, async (req: AuthenticatedRequest, res: Response) => {
    try {
        req.body.user = !req.body.user ? req.user?._id : req.body.user;
        if (!req.body.date) {
            req.body.date = new Date().toISOString();
        }
        const addedTrainingLogStatus = await _db.addTrainingLog(req.body);
        if (typeof addedTrainingLogStatus === "boolean") {
            if (!addedTrainingLogStatus) {
                res.status(500).send();
                return;
            }
        } else {
            const err = addedTrainingLogStatus as Error;
            if (err.message === "Document failed validation") {
                const mongoError = addedTrainingLogStatus as MongoServerError;
                res.status(400).send(`Provided training log schema invalid: ${JSON.stringify(mongoError.errInfo?.details)}`);
                return;
            } else if (err instanceof AnimalOwnerUserMismatchError) {
                res.status(400).send(`${err.message}`);
                return;
            } else {
                res.status(500).send(`Error in Training Log creation: ${err.message}`);
                return;
            }
        }
    } catch (err) {
        res.status(500).send(`Error in Training Log creation: ${(err as Error).message}`);
        return;
    }
    res.status(200).send();
});

app.get("/api/admin/users", authenticateToken, async (req: AuthenticatedRequest, res: Response) => {
    let pageNum = 1;
    let pageSize = 5;
    try {
        if (req.query.pageNum && !(req.query.pageNum instanceof Array)) {
            pageNum = Number.parseInt(req.query.pageNum as any);
        }
        if (req.query.pageSize && !(req.query.pageSize instanceof Array)) {
            pageSize = Number.parseInt(req.query.pageSize as any);
        }
        if (Number.isNaN(pageSize) || Number.isNaN(pageNum)) {
            throw new Error();
        }
    } catch (err) {
        res.status(500).send("Error parsing query parameters.");
    }
    try {
        const users = await _db.getUsers(pageSize, pageNum);
        res.json(users);
    } catch {
        res.status(500).send();
    }
});

app.get("/api/admin/animals", authenticateToken, async (req: AuthenticatedRequest, res: Response) => {
    let pageNum = 1;
    let pageSize = 5;
    try {
        if (req.query.pageNum && !(req.query.pageNum instanceof Array)) {
            pageNum = Number.parseInt(req.query.pageNum as any);
        }
        if (req.query.pageSize && !(req.query.pageSize instanceof Array)) {
            pageSize = Number.parseInt(req.query.pageSize as any);
        }
        if (Number.isNaN(pageSize) || Number.isNaN(pageNum)) {
            throw new Error();
        }
    } catch (err) {
        res.status(500).send("Error parsing query parameters.");
    }
    try {
        const animals = await _db.getAnimals(pageSize, pageNum);
        res.json(animals);
    } catch {
        res.status(500).send();
    }
});

app.get("/api/admin/training", authenticateToken, async (req: AuthenticatedRequest, res: Response) => {
    let pageNum = 1;
    let pageSize = 5;
    try {
        if (req.query.pageNum && !(req.query.pageNum instanceof Array)) {
            pageNum = Number.parseInt(req.query.pageNum as any);
        }
        if (req.query.pageSize && !(req.query.pageSize instanceof Array)) {
            pageSize = Number.parseInt(req.query.pageSize as any);
        }
        if (Number.isNaN(pageSize) || Number.isNaN(pageNum)) {
            throw new Error();
        }
    } catch (err) {
        res.status(500).send("Error parsing query parameters.");
    }
    try {
        const trainingLogs = await _db.getTrainingLogs(pageSize, pageNum);
        res.json(trainingLogs);
    } catch {
        res.status(500).send();
    }
});

app.post("/api/user/login", async (req: Request, res: Response) => {
    if (typeof req.body.email === "string" && typeof req.body.password === "string") {
        let user;
        try {
            user = await _db.getUserByEmail(req.body.email);
            if (!user) {
                res.status(403).send("Invalid email/password combo."); // invalid email
                return;
            }
            if (await bcrypt.compare(req.body.password, user.password)) {
                res.status(200).send();
                return;
            } else {
                res.status(403).send("Invalid email/password combo."); // invalid password
                return;
            }
        } catch (err) {
            res.status(500).send((err as Error).message);
            return;
        }
    } else {
        res.status(500).send("Invalid types of email and/or password.");
        return;
    }
});

app.post("/api/user/verify", async (req: Request, res: Response) => {
    if (typeof req.body.email === "string" && typeof req.body.password === "string") {
        let user;
        try {
            user = await _db.getUserByEmail(req.body.email);
            if (!user) {
                res.status(403).send("Invalid email/password combo."); // invalid email
                return;
            }
            if (await bcrypt.compare(req.body.password, user.password)) {
                const token = jwt.sign(user, process.env.JWT_STRING as string, { expiresIn: '9600s' });
                res.send(token);
                return;
            } else {
                res.status(403).send("Invalid email/password combo."); // invalid password
                return;
            }
        } catch (err) {
            res.status(500).send((err as Error).message);
            return;
        }
    } else {
        res.status(400).send("Invalid types of email and/or password.");
        return;
    }
});

app.post("/api/file/upload", authenticateToken, processUpload, async (req: FileUploadRequest, res: Response) => {
    try {
        const type = req.body.type;
        const validTypes: ValidUploadTypes = { animalProfilePicture: {
            field: "profilePicture",
            collection: "animals"
        }, userProfilePicture: {
            field: "profilePicture",
            collection: "users"
        }, trainingLogVideo: {
            field: "trainingLogVideo",
            collection: "trainingLogs"
        }};
        const id = req.body.id;
        if (!Object.keys(validTypes).includes(type)) {
            res.status(400).send("Invalid type supplied in request."); // I used error code 400 because that's the correct one
            return;
        }
        let objectExists = await _db.documentWithIdExists(id, (validTypes as any)[type].collection);
        if (!objectExists) {
            res.status(400).send("Object with provided id does not exist."); // I used error code 400 because that's the correct one
            return;
        }
        if ((type == "animalProfilePicture" || type == "userProfilePicture") && req.fileUpload?.data?.type !== "image") {
            res.status(400).send("Invalid file type (expected image).");
            return;
        }
        if ((type == "trainingLogVideo") && req.fileUpload?.data?.type !== "video") {
            res.status(400).send("Invalid file type (expected video).");
            return;
        }

        switch (type) {
            case "animalProfilePicture": {
                const animal = await _db.getAnimalById(id);
                if (animal.owner.toString() !== req.user?._id.toString()) {
                    res.status(400).send("Updated animal is not owned by the authenticated user.");
                    return;
                }
                break;
            }
            case "userProfilePicture": {
                if (req.user?._id.toString() !== id.toString()) {
                    res.status(400).send("Updated user is not the authenticated user.");
                    return;
                    // There should just be no id required because its stored in the JWT, but I mean...the readme says the id is provided
                }
                break;
            }
            case "trainingLogVideo": {
                const log = await _db.getTrainingLogById(id);
                if (log.user.toString() !== req.user?._id.toString()) {
                    res.status(400).send("Updated training log is not owned by the authenticated user.");
                    return;
                }
                break;
            }
        }

        const imagesRef = ref(storage, "images/");
        const videosRef = ref(storage, "videos/");
        let fileRef = req.fileUpload?.data?.type === "image" ? imagesRef : videosRef;
        fileRef = ref(fileRef, req.fileUpload?.name);
        const uploadResult = await uploadBytes(fileRef, req.file?.buffer as ArrayBuffer, { contentType: req.file?.mimetype });
        const downloadURL = await getDownloadURL(fileRef);
        if (uploadResult && downloadURL) {
            try {
                let updateObject: any = {};
                updateObject[(validTypes as any)[type].field] = downloadURL;
                switch (type) {
                    case "animalProfilePicture": {
                        await _db.updateAnimalById(id, updateObject);
                        break;
                    }
                    case "userProfilePicture": {
                        await _db.updateUserById(id, updateObject);
                        break;
                    }
                    case "trainingLogVideo": {
                        await _db.updateTrainingLogById(id, updateObject);
                        break;
                    }
                }
                res.status(200).send(downloadURL);
                return
            } catch (err) {
                console.error(err);
                res.status(500).send();
            }
        }
        res.status(500).send();
        return;
    } catch (err) {
        console.error(err);
        res.status(500).send();
        return;
    }
});

app.listen(APP_PORT, () => {
    console.log(`api listening at http://localhost:${APP_PORT}`)
});