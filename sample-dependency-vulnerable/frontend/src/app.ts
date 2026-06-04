import axios from "axios";
import lodash from "lodash";

export async function loadDashboard() {
  const response = await axios.get("/api/dashboard");
  return lodash.pick(response.data, ["projectName", "securityScore"]);
}
