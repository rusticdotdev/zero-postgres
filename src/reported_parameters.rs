use crate::error::{Error, Result};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReportedParameters {
    pub application_name: Option<String>,
    pub client_encoding: Option<String>,
    pub date_style: Option<String>,
    pub default_transaction_read_only: Option<bool>,
    pub in_hot_standby: Option<bool>,
    pub integer_datetimes: Option<bool>,
    pub interval_style: Option<String>,
    pub is_superuser: Option<bool>,
    pub scram_iterations: Option<u32>,
    pub search_path: Option<String>,
    pub server_encoding: Option<String>,
    pub server_version: Option<String>,
    pub session_authorization: Option<String>,
    pub standard_conforming_strings: Option<bool>,
    pub time_zone: Option<String>,
    pub unknowns: Vec<(String, String)>,
}

impl ReportedParameters {
    pub(crate) fn set<N, V>(&mut self, name: N, value: V) -> Result<()>
    where
        N: AsRef<str> + Into<String>,
        V: AsRef<str> + Into<String>,
    {
        match name.as_ref() {
            "application_name" => self.application_name = Some(value.into()),
            "client_encoding" => self.client_encoding = Some(value.into()),
            "DateStyle" => self.date_style = Some(value.into()),
            "default_transaction_read_only" => {
                self.default_transaction_read_only =
                    Some(parse_bool(name.as_ref(), value.as_ref())?)
            }
            "in_hot_standby" => {
                self.in_hot_standby = Some(parse_bool(name.as_ref(), value.as_ref())?)
            }
            "integer_datetimes" => {
                self.integer_datetimes = Some(parse_bool(name.as_ref(), value.as_ref())?)
            }
            "IntervalStyle" => self.interval_style = Some(value.into()),
            "is_superuser" => self.is_superuser = Some(parse_bool(name.as_ref(), value.as_ref())?),
            "scram_iterations" => {
                self.scram_iterations = Some(value.as_ref().parse().map_err(
                    |error: std::num::ParseIntError| {
                        Error::Decode(format!(
                            "reported parameter scram_iterations: {error}: {:?}",
                            value.as_ref()
                        ))
                    },
                )?)
            }
            "search_path" => self.search_path = Some(value.into()),
            "server_encoding" => self.server_encoding = Some(value.into()),
            "server_version" => self.server_version = Some(value.into()),
            "session_authorization" => self.session_authorization = Some(value.into()),
            "standard_conforming_strings" => {
                self.standard_conforming_strings = Some(parse_bool(name.as_ref(), value.as_ref())?)
            }
            "TimeZone" => self.time_zone = Some(value.into()),
            _ => {
                let unknown = self
                    .unknowns
                    .iter_mut()
                    .find(|(unknown_name, _)| unknown_name == name.as_ref());
                match unknown {
                    Some((_, unknown_value)) => *unknown_value = value.into(),
                    None => self.unknowns.push((name.into(), value.into())),
                }
            }
        }
        Ok(())
    }
}

fn parse_bool(name: &str, value: &str) -> Result<bool> {
    match value {
        "on" => Ok(true),
        "off" => Ok(false),
        _ => Err(Error::Decode(format!(
            "reported parameter {name}: expected on or off, got {value:?}"
        ))),
    }
}
