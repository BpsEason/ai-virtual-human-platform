FROM node:20-alpine

WORKDIR /app

# 複製 package.json 和 package-lock.json
COPY package*.json ./

# 安裝依賴
RUN npm install

# 複製所有檔案
COPY . .

# 編譯 TypeScript
RUN npm run build

# 啟動應用程式
CMD ["node", "dist/app.js"]
