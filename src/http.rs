pub fn get_client() -> Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder().build()
}
