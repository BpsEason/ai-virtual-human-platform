# 專案名稱

這是一個基於 Laravel 11、Vue 3 和微服務架構的完整專案範例。

## 技術棧

- **後端**: Laravel 11, Laravel Octane (Swoole), JWT Auth
- **微服務**:
  - **向量化服務**: Python (FastAPI, SentenceTransformer, Faiss)
  - **對話服務**: Node.js (gRPC, LangChain JS)
- **前端**: Vue 3, Vite, Pinia, Tailwind CSS
- **資料庫/快取**: MySQL 8.0, Redis 7.0, RabbitMQ 3.9
- **部署**: Docker, Docker Compose, Kubernetes, Helm
- **CI/CD**: GitHub Actions

## 開始使用

### 1. 專案初始化

執行以下腳本來自動生成所有專案檔案和目錄結構：

```bash
bash generate_project.sh
```

### 2. 開發環境設置

使用 Docker Compose 啟動所有服務：

```bash
./scripts/dev-setup.sh
```

### 3. 執行建構

執行建構所有服務的腳本：

```bash
./scripts/build.sh
```

### 4. 執行測試

執行所有後端和微服務的單元測試和整合測試：

```bash
./scripts/test.sh
```

### 5. 部署

使用 Helm 將應用程式部署到 Kubernetes：

```bash
./scripts/deploy-helm.sh
```
