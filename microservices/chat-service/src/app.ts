import { Server, ServerCredentials } from '@grpc/grpc-js';
import { loadSync } from '@grpc/proto-loader';
import { ProtoGrpcType } from './proto/chat';
import { ChatServiceHandlers } from './proto/chat/ChatService';
import { ChatRequest } from './proto/chat/ChatRequest';
import { ChatReply } from './proto/chat/ChatReply';
import { OpenAI } from '@langchain/openai';
import { PineconeClient } from '@pinecone-database/pinecone';

const PROTO_PATH = __dirname + '/proto/chat.proto';
const packageDefinition = loadSync(PROTO_PATH, { keepCase: true, longs: String, enums: String, defaults: true, oneofs: true });
const proto = (packageDefinition as unknown) as ProtoGrpcType;

const server = new Server();

const chatService: ChatServiceHandlers = {
    SendMessage: async (call, callback) => {
        const { message } = call.request;
        console.log(`Received message: ${message}`);

        // 初始化 Pinecone
        const pinecone = new PineconeClient({
            apiKey: process.env.PINECONE_API_KEY!,
            environment: process.env.PINECONE_ENVIRONMENT!,
        });
        const index = pinecone.Index('my-index');

        // 使用 LangChain 與 Pinecone 進行 RAG
        const model = new OpenAI({
            openAIApiKey: process.env.OPENAI_API_KEY,
            temperature: 0.9,
        });

        // 假設向量由前端或另一服務提供，實際應調用向量化服務
        const queryVector = await fetch('http://vectorization-service:8000/vectorize', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ content: message })
        }).then(res => res.json()).then(data => data.vector);

        const result = await index.query({
            vector: queryVector,
            topK: 5,
            includeValues: true,
            includeMetadata: true
        });

        const context = result.matches.map((m: any) => m.metadata?.content || '').join('\n');
        const response = await model.call(`Context: ${context}\n\nQuestion: ${message}`);
        
        callback(null, { reply: response });
    }
};

server.addService(proto.chat.ChatService.service, chatService);
server.bindAsync('0.0.0.0:50051', ServerCredentials.createInsecure(), (err, port) => {
    if (err) {
        console.error(err);
        return;
    }
    console.log(`gRPC server listening on ${port}`);
    server.start();
});
