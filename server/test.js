const express = require('express')
const app = express()

const bodyParser = require('body-parser')
const cors = require('cors')

const jwt = require('jsonwebtoken')
const jwksClient = require('jwks-rsa');

app.use(bodyParser.json())
app.use(cors())

const client = jwksClient({
  jwksUri: 'https://sandrino.auth0.com/.well-known/jwks.json',
  
});


function getAppleSigningKey(kid){
    return new Promise((resolve) => {


        client.getSigningKey(kid, (err, key) => {
            if(err){
                console.error(err)
                resolve(null)
            }
            const signingKey = key.getPublicKey();
            resolve(signingKey)
            // Now I can use this to configure my Express middleware
        });
        
    })
}

function verifyJWT(json, publickey){
    return new Promise((resolve) => {
        jwt.verify(json, publickey, (err, payload) => {
            if (err) {
                console.error(err)
                return resolve(err)
            }

            resolve(payload)
        })
    })
}

app.post('/login',async (req , res)=>{
    try{
        console.log(req.body)

        const { response } = req.body;

        if(response){
            const {identityToken , user } = response.response ;
            
            const json = jwt.decode(identityToken,{complete : true});
            const kid = json.header.kid

            const appleKey = await getAppleSigningKey(kid)

            if(!appleKey) {
                console.error('Error Occured somewhere')
                return
            }

           const payload =  await verifyJWT(identityToken, appleKey)

           if(!payload){
               console.error('error occured')
               return
           }
           console.log('Sign is successful',payload)
        }
        res.json({status:'PASS'})

    }catch(err){
        res.send({status:'FAIL',message:err.message})
    }
})

app.listen(9000,()=>{
    console.log('app listening to 9000')
})