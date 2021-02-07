require('dotenv').config()
const express = require('express');
const { graphqlHTTP } = require('express-graphql');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const path = require('path');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const graphqlSchema = require('./graphql/schema');
const graphqlResolver = require('./graphql/resolvers');
const auth = require('./middleware/auth');

const config = require('./config.json');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3001;

const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'images');
    },
    filename: function (req, file, cb) {
        cb(null, `${uuidv4()}${path.extname(file.originalname)}`)
    }
});

const fileFilter = (req, file, cb) => {
    if (
        file.mimetype === 'image/png' ||
        file.mimetype === 'image/jpg' ||
        file.mimetype === 'image/jpeg'
    ) {
        cb(null, true);
    } else {
        cb(null, false);
    }
};

app.use(bodyParser.json());
app.use(multer({ storage: storage, fileFilter: fileFilter }).single('image'));
app.use('/images', express.static(path.join(__dirname, 'images')));

app.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader(
        'Access-Control-Allow-Methods',
        'OPTIONS, GET, POST, PUT, PATCH, DELETE'
    );
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    if (req.method === 'OPTIONS') {
        return res.sendStatus(200)
    }
    next();
});

app.use(auth);

app.put('/post-image', (req, res, next) => {

    if(!req.isAuth){
        throw new Error('Not Authenticated');
    }

    if (!req.file) {
        return res.status(200).send({ message: 'No file provided' })
    }

    if(req.body.oldPath){
        clearImage(req.body.oldPath);
    }

    const updatedFilePath = (req.file.path).replace("\\", "/");

    return res.status(201).send({message: 'file stored', path: updatedFilePath})
})
app.use(auth);
app.use('/graphql',
    graphqlHTTP({
        schema: graphqlSchema,
        rootValue: graphqlResolver,
        graphiql: true,
        formatError(err) {
            if (!err.originalError) {
                return err
            }
            const data = err.originalError.data;
            const message = err.message || 'An error occured';
            const code = err.originalError.code || 500;

            return { message: message, statusCode: code, data: data }
        }
    })
);


app.use((error, req, res, next) => {
    console.log(error);
    const status = error.statusCode || 500;
    const message = error.message;
    const data = error.data;
    res.status(status).json({ message: message, data: data });
});

mongoose
    .connect(config.mongodbURL, { useNewUrlParser: true, useUnifiedTopology: true })
    .then((result) => {
        console.log('connected');
        app.listen(config.port, () => console.log(`Server running at port ${config.port}`));
    })
    .catch((err) => {
        console.log('Error => ', err)
    })


const clearImage = filePath => {
    filePath = path.join(__dirname, '..', filePath);
    fs.unlink(filePath, err => console.log(err));
};