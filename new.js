addEventListener("fetch", (event) => {
    event.passThroughOnException();
    event.respondWith(handleRequest(event.request));
  });
  
  const dockerHub = "https://registry-1.docker.io";
  
  const routes = {
    // production
    ["docker." + "bothyi.top"]: dockerHub,
    ["quay." + "bothyi.top"]: "https://quay.io",
    ["gcr." + "bothyi.top"]: "https://gcr.io",
    ["k8s-gcr." + "bothyi.top"]: "https://k8s.gcr.io",
    ["k8s." + "bothyi.top"]: "https://registry.k8s.io",
    ["ghcr." + "bothyi.top"]: "https://ghcr.io",
    ["cloudsmith." + "bothyi.top"]: "https://docker.cloudsmith.io",
    ["ecr." + "bothyi.top"]: "https://public.ecr.aws",
  
    // staging
    ["docker-staging." + "bothyi.top"]: dockerHub,
  };
  
  function routeByHosts(host) {
    if (host in routes) {
      return routes[host];
    }
    if (MODE == "debug") {
      return TARGET_UPSTREAM;
    }
    return "";
  }
  
  async function handleRequest(request) {
    //打印所有请求
    console.log("============请求来了 start============");
    console.log("request.url",request.url);
    console.log("request.method",request.method);
    //这里变量request.headers是一个对象，需要转换为字符串
    let headers = "";
    for (const [key, value] of request.headers.entries()) {
        headers += `${key}: ${value}\n`;
    }
    console.log("request.headers",headers);
    console.log("request.body",request.body);
    console.log("request.authorization",request.headers.get("Authorization"));
    console.log("============请求来了 end============");
    const url = new URL(request.url);
    const upstream = routeByHosts(url.hostname);
    if (upstream === "") {
      return new Response(
        JSON.stringify({
          routes: routes,
        }),
        {
          status: 404,
        }
      );
    }
    const isDockerHub = upstream == dockerHub;
    const authorization = request.headers.get("Authorization");
    if (url.pathname == "/v2/") {
        console.log("============进入v2============");
      const newUrl = new URL(upstream + "/v2/");
      const headers = new Headers();
      if (authorization) {
        headers.set("Authorization", authorization);
      }
      // check if need to authenticate
      const resp = await fetch(newUrl.toString(), {
        method: "GET",
        headers: headers,
        redirect: "follow",
      });
      if (resp.status === 401) {
        console.log("============进入401 start============");
        console.log("resp.status",resp.status);
        console.log("resp.headers",resp.headers);
        console.log("resp.body",resp.body);
        console.log("url",url);
        console.log("============进入401 end============");
        return responseUnauthorized(url);
      }
      return resp;
    }
    // get token
    if (url.pathname == "/v2/auth") {
        console.log("============进入v2/auth============");
      const newUrl = new URL(upstream + "/v2/");
      const resp = await fetch(newUrl.toString(), {
        method: "GET",
        redirect: "follow",
      });
      if (resp.status !== 401) {
        return resp;
      }
      const authenticateStr = resp.headers.get("WWW-Authenticate");
      if (authenticateStr === null) {
        return resp;
      }
      const wwwAuthenticate = parseAuthenticate(authenticateStr);
      let scope = url.searchParams.get("scope");
      // autocomplete repo part into scope for DockerHub library images
      // Example: repository:busybox:pull => repository:library/busybox:pull
      if (scope && isDockerHub) {
        let scopeParts = scope.split(":");
        if (scopeParts.length == 3 && !scopeParts[1].includes("/")) {
          scopeParts[1] = "library/" + scopeParts[1];
          scope = scopeParts.join(":");
        }
      }
      return await fetchToken(wwwAuthenticate, scope, authorization);
    }
    // redirect for DockerHub library images
    // Example: /v2/busybox/manifests/latest => /v2/library/busybox/manifests/latest
    if (isDockerHub) {
      const pathParts = url.pathname.split("/");
      if (pathParts.length == 5) {
        pathParts.splice(2, 0, "library");
        const redirectUrl = new URL(url);
        redirectUrl.pathname = pathParts.join("/");
        return Response.redirect(redirectUrl, 301);
      }
    }
    // foward requests
    const newUrl = new URL(upstream + url.pathname);
    const newReq = new Request(newUrl, {
      method: request.method,
      headers: request.headers,
      // don't follow redirect to dockerhub blob upstream
      redirect: isDockerHub ? "manual" : "follow",
    });
    const resp = await fetch(newReq);
    if (resp.status == 401) {
      return responseUnauthorized(url);
    }
    // handle dockerhub blob redirect manually
    if (isDockerHub && resp.status == 307) {
      const location = new URL(resp.headers.get("Location"));
      const redirectResp = await fetch(location.toString(), {
        method: "GET",
        redirect: "follow",
      });
      return redirectResp;
    }
    return resp;
  }
  
  function parseAuthenticate(authenticateStr) {
    // sample: Bearer realm="https://auth.ipv6.docker.com/token",service="registry.docker.io"
    // match strings after =" and before "
    const re = /(?<=\=")(?:\\.|[^"\\])*(?=")/g;
    const matches = authenticateStr.match(re);
    if (matches == null || matches.length < 2) {
      throw new Error(`invalid Www-Authenticate Header: ${authenticateStr}`);
    }
    return {
      realm: matches[0],
      service: matches[1],
    };
  }
  
  async function fetchToken(wwwAuthenticate, scope, authorization) {
    console.log("============进入fetchToken============");
    const url = new URL(wwwAuthenticate.realm);
    if (wwwAuthenticate.service.length) {
        url.searchParams.set("service", wwwAuthenticate.service);
    }
    if (scope) {
        url.searchParams.set("scope", scope);
    }
    const headers = new Headers();
    if (authorization) {
        headers.set("Authorization", authorization);
    }
    return await fetch(url, { method: "GET", headers: headers });
}

  function responseUnauthorized(url) {
    console.log("============进入responseUnauthorized start============");
    const headers = new(Headers);
    if (MODE == "debug") {
      headers.set(
        "Www-Authenticate",
        `Bearer realm="http://${url.host}/v2/auth",service="cloudflare-docker-proxy"`
      );
    } else {
      headers.set(
        "Www-Authenticate",
        `Bearer realm="https://${url.hostname}/v2/auth",service="cloudflare-docker-proxy"`
      );
    }
    let headersStr = "";
    for (const [key, value] of headers.entries()) {
        headersStr += `${key}: ${value}\n`;
    }
    console.log("headers",headersStr);
    console.log("url",url);
    console.log("============进入responseUnauthorized end============");
    return new Response(JSON.stringify({ message: "UNAUTHORIZED" }), {
      status: 401,
      headers: headers,
    });
  }