const express = require('express');
const fs = require('fs');

require('dotenv').config();
const { createAppAuth, createOAuthUserAuth } = require("@octokit/auth-app");
const {request} = require("@octokit/request");

// Read the private key for app authentication.
const privateKey = fs.readFileSync('myappzrk.2022-03-06.private-key.pem');

const port = process.env.PORT
const APP_IDENTIFIER = process.env.GITHUB_APP_IDENTIFIER
const clientId = process.env.CLIENT_ID
const clientSecret = process.env.CLIENT_SECRET
const installation_id = process.env.INSTALL_ID

// This function checks if a new repo is created and calls protect_main_branch function if true.
function checkIfNewRepoCreated(req,res,next){
    if (('repository' in req.body && req.body.action=="created")||('repository' in req.body && req.body.ref=="main")){
        console.log("New repository created: "+ req.body.repository.name);
    }
    next();
}

// This function automates the process of protecting the default branch.
async function protect_main_branch(req,res,next){
    // Authorize the github app installed on organization to run branch protection API.
    const auth = createAppAuth({
        appId: APP_IDENTIFIER,
        privateKey,
        // The installation ID can be obtained from url when a Github app is installed on the organization.
        installationId: installation_id,
        clientId: clientId.toString(),
        clientSecret: clientSecret.toString()
    });
    const { token } = await auth({ type: "installation" });
    const repo = req.body.repository.name.toString()
    const branch = 'main'
    const owner = req.body.repository.owner.login.toString()
    const result = await request('PUT /repos/{owner}/{repo}/branches/{branch}/protection',{
        headers: {
            authorization: "token " + token,
            accept: 'application/vnd.github.v3+json',
          },
        required_status_checks: null,
        required_pull_request_reviews: { required_approving_review_count: 2},
        enforce_admins: null,
        restrictions: null,
        owner,
        repo,
        branch
    })
    console.log("Default branch protected.")
    next();
}

// This function notifies user of the branch protection added in the issues section.
async function notify_user(req,res,next){

    const owner = req.body.repository.owner.login
    const repo = req.body.repository.name
    const username = req.body.sender.login
    const help_url = 'https://help.github.com/en/articles/about-protected-branches'
    const branch = 'main'
    const issue_title = 'Default Branch Protected.'
    const issue_body = `@${username}: Branch protection rules have been added to the ${branch} branch.\
    \n- Collaborators cannot force push to a protected branch or delete the branch\
    \n- All commits must be made to a non-protected branch and submitted via a pull request\
    \n- There must be least 2 approving reviews and no changes requested before a PR can be merged\
    \n\n **Note:** All configured restrictions are enforced for administrators.\
    \n You can learn more about protected branches here: [About protected branches - GitHub Help](${help_url})`;
    const auth = createAppAuth({
        appId: APP_IDENTIFIER,
        privateKey,
        // The installation ID can be obtained from url when a Github app is installed on the organization.
        installationId: installation_id,
        clientId: clientId.toString(),
        clientSecret: clientSecret.toString()
    });
    const { token } = await auth({ type: "installation" });
    const result = await request('POST /repos/{owner}/{repo}/issues',{
        headers:{
            authorization: "token " + token,
            accept: 'application/vnd.github.v3+json',
        },
        owner,
        repo,
        title:issue_title,
        body:issue_body,  
    })
    console.log("Issue written.")
    next()
}

// MAIN
const app = express();
app.use(express.json());

// Register path /payload to check if a new repo is created, protect branch and notify user.
// app.post('/payload',authenticate,(req,res)=>{
//     res.status(200).send('App authenticated.\n')
// })

app.post('/new-repo',checkIfNewRepoCreated,protect_main_branch,notify_user,(req,res)=>{
    res.status(200).send('Default branch protected. Issue created.\n');
})

app.use((err, req, res, next) => {
    if (err) console.error(err)
    res.status(403).send('Request body was not signed or verification failed.')
})

app.listen(port, () => console.log(`Listening on port ${port}`));