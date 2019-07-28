import { proxy, createServer } from 'aws-serverless-express';
import { Context } from 'aws-lambda';
import { Server } from 'http';

import app from './app';

const server = createServer(app);

exports.handler = (event: any, context: Context): Server => {
  return proxy(server, event, context);
};