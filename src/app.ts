import express from 'express';
import cors from 'cors';
import serverlessMiddleware from 'aws-serverless-express/middleware';

const app = express();

app.use(serverlessMiddleware.eventContext());
app.use(cors());
app.use(express.json());
app.use(express.urlencoded());

// app.use('/root-path', router);

export default app;