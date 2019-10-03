const request = require('request');

const SKEY = process.env.SKEY; //secret key provided by google recaptcha
const API_URL = process.env.API_URL; //'https://www.google.com/recaptcha/api/siteverify'
const corsWhitelist = process.env.WHITELISTEDORIGINS.split(','); //whitelist your event.header.origin(s)

exports.handler = async (event, context) => {
  //we always want to return 200 so that the requesting URL can have good feedback to work with
  let response = {
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Methods": "POST"
    },
    statusCode: 200,
  };
  //check origin for CORs
  if (event.headers && corsWhitelist.indexOf(event.headers.origin) !== -1) {
    response.headers['Access-Control-Allow-Origin'] = event.headers.origin;
    response.headers['Access-Control-Allow-Headers'] = 'Origin, X-Requested-With, Content-Type, Accept';

    //send the event body to verify the recaptcha response
    let validity = !!event.body ? await checkRecaptcha(JSON.parse(event.body)) : {
      errors: ['There was an issue with response sent, please try again.']
    }; //body should be sent { recaptcha: CODE_RETURNED_FROM_BROWSER }

    response.body = JSON.stringify(validity); //pass the recaptcha response back to requester
  }
  else {
    response.statusCode = 400;
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
      } else {
        //parse the response body
        let jsonRes = JSON.parse(body);

        if (!jsonRes.success || (!!jsonRes['error-codes'] && jsonRes['error-codes'].length > 0)) { //failure
          errors.push('There was an issue with response sent, please try again.');
          errors.concat(jsonRes['error-codes']);
        }
        //return any errors and the success status
        resolve({
          errors: jsonRes['error-codes'],
          success: jsonRes.success
        });
      }
    });
  });
}