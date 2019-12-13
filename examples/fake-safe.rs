extern crate macaroon;
extern crate serde_json;
extern crate chrono;

use macaroon::macaroon::{Macaroon, Caveat};
use macaroon::verifier::Verifier;
use sodiumoxide::crypto::auth;
use sodiumoxide::crypto::auth::hmacsha512256::Key;

fn authenticator() -> (Key, Macaroon ) {
	// Construct a macaroon and serialize it
	let secret_key = auth::gen_key();
	let identifier = "App1";
	let mut macaroon = Macaroon::new(&secret_key, identifier.into(), None).unwrap();
	let data = serde_json::to_string(&macaroon).unwrap();

	(secret_key, macaroon)
	// println!("initial macaroon: {}", data);
	// println!("secret_key used was: {:?}", &secret_key);
}

fn permission_request( macaroon: &mut Macaroon ) {
	macaroon.add_first_party_caveat(Caveat{
		identifier: "labels = [bacon, sandwhich]".into(),
		..Default::default()
	}).unwrap();




	let expire = chrono::Utc::now() + chrono::Duration::hours(5);
	macaroon.add_first_party_caveat(Caveat{
	    identifier: format!("time < {}", expire.to_rfc3339()).into(),
	    ..Default::default()
	}).unwrap();

	let data = serde_json::to_string(&macaroon).unwrap();

	println!("this time with caveeats (and serialised): {}", data);


	let deserialized: Macaroon = serde_json::from_str(&data).unwrap();
	println!("this time with caveeats (and deserialized): {:?}", deserialized);

	println!("so lets check if the deserialized sig matches macaroon sig: {:?}", deserialized.signature == macaroon.signature);


}


fn is_valid_at_client_handler( macaroon: &Macaroon, secret_key: Key ) -> bool {

    // Succeeding verification
    let mut v = Verifier::default();

	// aha, things to check when we call verify
    v.satisfy_exact("labels = [bacon, sandwhich]".into());
    // v.satisfy_exact("user = me".into());

	println!("About to mess with sig");

    // Could also check it's no expired here...
    v.satisfy_general(Box::new(is_expired));

	// we check that the macaroon is valid by comparing to auth stored secret key.
    v.verify(&macaroon, &secret_key, Vec::new()).unwrap();

	true


}

// we could pass a signed message if we want to establish ownership etc....
fn is_valid_at_data_handler( perms: Vec<String>, _signed_message: Option<String> ) -> bool {
	// TODO, check perms / labels.

	println!("perms received for check, {:?}", perms );

	true

}


fn get_perms_for_app( macaroon: &Macaroon ) -> Vec<String> {
	let caveats = macaroon.get_first_party_caveats().clone();

	let mut perms = vec![];
	for cav in &caveats {
		// println!("\n\nCaveats found:: {:?}", cav.identifier.0 );
		// println!("\n\nCaveats found:: {:?}", std::str::from_utf8( &cav.identifier.0 ) );
		perms.push(std::str::from_utf8( &cav.identifier.0 ).unwrap().to_string());
	}

	perms
}

fn main() {

	let ( secret_key, mut macaroon ) = authenticator();

	println!("KEY {:?}", secret_key);
	println!("macaroon {:?}", macaroon);

	// lets get our permission...
	permission_request( &mut macaroon );

	//client handler checks
	is_valid_at_client_handler( &macaroon, secret_key );

	let perms = get_perms_for_app( &macaroon );
	println!("perms found {:?}", perms);

	is_valid_at_data_handler(perms, None);

}

fn is_expired(c: &Caveat) -> bool {
    let prefix = "time < ".as_bytes();
    if !c.identifier.0.starts_with(&prefix) {
        return false
    }
    let time_str = match std::str::from_utf8(c.identifier.0.split_at(prefix.len()).1) {
        Ok(s) => s,
        Err(_) => return false
    };
    let time = match time_str.parse::<chrono::DateTime<chrono::Utc>>() {
        Ok(t) => t,
        Err(_) => return false
    };
    let now = chrono::Utc::now();
    return time >= now
}
