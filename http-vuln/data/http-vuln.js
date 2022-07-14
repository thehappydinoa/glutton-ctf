module.exports = [
  {
    request: {
      url: "/",
      method: "get",
      protocol: "http",
    },
    response: {
      delay: 1,
      status: 200,
      headers: {
        "Content-Type": "application/json; charset=UTF-8",
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Headers":
          "Origin, X-Requested-With, Content-Type, Accept",
        Server: "nginx/1.20.0",
        "X-Powered-By": "caffine",
        "X-Script":
          '<img src=http://i.giphy.com/sMjmhaWPuzFHa.gif> <script>alert("XSS")</script>',
      },
      body: {
        result: true,
        key: "ctf{1effcc39-de5e-4636-9513-53450d87ce79}",
      },
    },
  },
];
