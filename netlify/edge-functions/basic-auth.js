export default async (request, context) => {
  const auth = request.headers.get("authorization");
  const user = Deno.env.get("SITE_USER");
  const pass = Deno.env.get("SITE_PASS");

  if (auth) {
    const [scheme, encoded] = auth.split(" ");
    if (scheme === "Basic" && encoded) {
      const decoded = atob(encoded);
      const [u, p] = decoded.split(":");
      if (u === user && p === pass) {
        return context.next();
      }
    }
  }

  return new Response("Authentication required", {
    status: 401,
    headers: {
      "WWW-Authenticate": 'Basic realm="Chop\'s Haven Security Reports"',
    },
  });
};

export const config = { path: "/*" };