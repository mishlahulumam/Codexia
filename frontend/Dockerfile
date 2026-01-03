FROM node:20-alpine AS builder
WORKDIR /app
COPY package.json ./
COPY tsconfig.json ./
COPY vite.config.ts ./
COPY index.html ./
ARG VITE_API_BASE
ENV VITE_API_BASE=${VITE_API_BASE}
RUN npm install
COPY src ./src
RUN npm run build

FROM node:20-alpine
WORKDIR /app
RUN npm install -g serve
COPY --from=builder /app/dist /app/dist
EXPOSE 5173
CMD ["serve", "-s", "dist", "-l", "5173"]
