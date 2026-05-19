# build environment
FROM node:25-alpine as build
WORKDIR /app
COPY package.json yarn.lock ./
RUN yarn install --frozen-lockfile
COPY . .
RUN yarn build

# production environment
FROM node:25-alpine
COPY --from=build /app/dist .
ENTRYPOINT sh -c "node ."
