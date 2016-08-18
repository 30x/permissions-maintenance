FROM mhart/alpine-node:4

WORKDIR /app
ADD package.json .
RUN npm install
ADD . .

ENV COMPONENT="permissions-maintenance" 
ENV PORT=3000
EXPOSE 3000
CMD ["node", "permissions-maintenance.js"]