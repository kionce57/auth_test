# Stage 1: Build
FROM node:18-alpine AS builder

WORKDIR /app

# 複製依賴檔案
COPY package.json package-lock.json ./
RUN npm ci

# 複製程式碼並建置
COPY . .
RUN npm run build

# Stage 2: Production
FROM nginx:alpine

# 複製建置產物
COPY --from=builder /app/dist /usr/share/nginx/html

# 複製 nginx 設定
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
