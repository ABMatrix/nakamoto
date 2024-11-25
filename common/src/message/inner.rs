use bitcoin::network::message::{CommandString, NetworkMessage, RawNetworkMessage};
use crate::message::dogecoin_message::{DogeCoinNetworkMessage, DogeCoinRawNetworkMessage};

/// Self defined RawNetWorkMessage to send both btc message and doge message
#[derive(Clone, Debug)]
pub enum InnerRawNetWorkMessage {
    /// BTC raw message
    BTC(RawNetworkMessage),
    /// DOGE raw message
    DOGE(DogeCoinRawNetworkMessage)
}

impl InnerRawNetWorkMessage {
    /// Return the message command as a static string reference.
    pub fn cmd(&self) -> &'static str {
        match self {
            InnerRawNetWorkMessage::BTC(msg) => msg.cmd(),
            InnerRawNetWorkMessage::DOGE(msg   ) => {
                let msg: RawNetworkMessage = msg.into();
                msg.cmd()
            }
        }
    }

    /// Return the CommandString for the message command.
    pub fn command(&self) -> CommandString {
        match self {
            InnerRawNetWorkMessage::BTC(msg) => msg.command(),
            InnerRawNetWorkMessage::DOGE(msg   ) => {
                let msg: RawNetworkMessage = msg.into();
                msg.command()
            }
        }
    }

    /// Returns the magic
    pub fn magic(&self) -> u32 {
        match self {
            InnerRawNetWorkMessage::BTC(msg) => msg.magic,
            InnerRawNetWorkMessage::DOGE(msg   ) => msg.magic
        }
    }

    /// Returns the payload
    pub fn payload(self) -> InnerNetWorkMessage {
        match self {
            InnerRawNetWorkMessage::BTC(msg) => InnerNetWorkMessage::BTC(msg.payload),
            InnerRawNetWorkMessage::DOGE(msg   ) => InnerNetWorkMessage::DOGE(msg.payload)
        }
    }
}

/// Self defined NetWorkMessage to send both btc message and doge message
#[derive(Clone, Debug)]
pub enum InnerNetWorkMessage {
    /// BTC raw message
    BTC(NetworkMessage),
    /// DOGE raw message
    DOGE(DogeCoinNetworkMessage)
}

impl From<InnerNetWorkMessage> for NetworkMessage {
    fn from(value: InnerNetWorkMessage) -> Self {
        match value {
            InnerNetWorkMessage::BTC(msg) => msg,
            InnerNetWorkMessage::DOGE(msg) => msg.into()
        }
    }
}

impl InnerNetWorkMessage {
    /// Return the message command as a static string reference.
    pub fn cmd(&self) -> &'static str {
        match self {
            InnerNetWorkMessage::BTC(msg) => msg.cmd(),
            InnerNetWorkMessage::DOGE(msg   ) => {
                let msg: NetworkMessage = msg.into();
                msg.cmd()
            }
        }
    }


}
