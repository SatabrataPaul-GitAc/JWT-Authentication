const HTTPError = function HTTPError(statusCode, message) {
    const error = {
        statusCode,
        message
    };
    return error;
  };
  
  module.exports = HTTPError;