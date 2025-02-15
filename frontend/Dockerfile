FROM node:18 as build-stage

WORKDIR /app

COPY package.json ./

RUN npm install

COPY . .

EXPOSE 3000
CMD ["npm", "run", "dev"] # We are in beta test now, for now this should be in dev mode.
