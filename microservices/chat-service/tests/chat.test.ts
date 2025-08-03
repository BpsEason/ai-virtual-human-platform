import { Server, ServerCredentials } from '@grpc/grpc-js';
import { ChatServiceClient } from '../src/proto/chat';

describe('ChatService', () => {
    let client: ChatServiceClient;
    beforeAll((done) => {
        const server = new Server();
        server.bindAsync('localhost:50051', ServerCredentials.createInsecure(), () => {
            client = new ChatServiceClient('localhost:50051', ServerCredentials.createInsecure());
            done();
        });
    });

    it('should respond to SendMessage', (done) => {
        client.SendMessage({ message: 'Hello' }, (err, response) => {
            expect(err).toBeNull();
            expect(response.reply).toBeDefined();
            done();
        });
    });
});
