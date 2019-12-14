
const { createWriteStream } = require("fs");

const uploadDir = './uploads'

const storeUpload = ({ stream, filename }) =>
  new Promise((resolve, reject) =>
    stream
      .pipe(createWriteStream(uploadDir+filename))
      .on("finish", () => resolve())
      .on("error", reject)
  );

  module.exports = storeUpload;



