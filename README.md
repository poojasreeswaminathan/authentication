# Netlify Template

Use this template to create a react app with backend to be deployed to Netlify.

## How to use

1. Clone this repo using git or use "Download Zip" option in Github
2. Open the folder in VS Code
3. Install dependencies

```sh
npm install
```

4. Add `.env` file with `MONGO_URI` if you are using mongodb
5. Run the vite server

```sh
npm run dev
```

## Manual Steps

1. Create react project using vite

```sh
npm create vite -- -t react netlify-template
```

2. Open newly created folder in VS Code
3. Install dependencies

```sh
npm install
```

4. Install dependencies for backend with netlify related packages

```sh
npm install express mongoose dotenv serverless-http
```

5. Create a folder called `functions`
6. Add express API code in a separate file called `app.js`, exclude `app.listen` code.
7. Import the `app` from `app.js` and add `app.listen` code as given below in another file called `app-local.js`

```js
import { app } from "./app.js";

app.listen(5000, () => {
  console.log("Server started at 5000");
});
```

8. Import the `app` from `app.js` and add below code in another file called `app-netlify.js`

```js
import serverless from "serverless-http";

import { app } from "./app.js";

export const handler = serverless(app);
```

9. Create a file called `netlify.toml` at the top level with below content

```toml
[functions]
  external_node_modules = ["express"]
  node_bundler = "esbuild"
[[redirects]]
  force = true
  from = "/api/*"
  status = 200
  to = "/.netlify/functions/app-netlify/:splat"
```
