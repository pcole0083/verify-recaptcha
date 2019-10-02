const request = require('request');

const SKEY = process.env.SKEY; //secret key provided by google recaptcha
const API_URL = process.env.API_URL; //'https://www.google.com/recaptcha/api/siteverify'

exports.handler = async (event) => {
  //we always want to return 200 so that the requesting URL can have good feedback to work with
  let response = {
    statusCode: 200,
  };
  //send the event body to verify the recaptcha response
  let validity = await checkRecaptcha(event.body); //body should be sent { recaptcha: CODE_RETURNED_FROM_BROWSER }

  if (validity.errors && validity.errors.length) {
    response.body = JSON.stringify(validity.errors); //respond with errors
  } else {
    response.body = JSON.stringify(validity.success); //respond with success
  }
  return response;
};

function checkRecaptcha(f) {
  //wrap promise around the request as it is and asyc action
  return new Promise((resolve, reject) => {
    //collect errors here
    let errors = [];
    //send the post request
    request.post(API_URL, {
      form: {
        secret: SKEY,
        response: f.recaptcha
      }
    }, (err, resp, body) => {
      //handle error codes first
      if (err) {
        errors.push(err);
        resolve({
          errors: errors,
          success: false
        });
      }
      else {
        //parse the response body
        let jsonRes = JSON.parse(body);

        if (!jsonRes.success) { //failure
          errors.push('You did not fill out the recaptcha or resubmitted the form.');
        }
        //return any errors and the success status
        resolve({
          errors: errors,
          success: jsonRes.success
        });
      }
    });
  });
}