

const sample_shield_login_fn = async (req, res) => {

  // health check
  if (req.params["health"] === "health") {
    res.write(JSON.stringify({success: true, msg: "Health check success"}))
    res.end()
  }

  // Add your code here
  res.write(JSON.stringify({success: true, msg: `Hello sample_shield_login_fn`}))
  res.end()
  
}

export default sample_shield_login_fn
