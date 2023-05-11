impl TryFrom<crate::proto::biurs_v1::ListResponse> for Vec<crate::types::Metadata> {
    type Error = crate::types::TypeError;

    fn try_from(value: crate::proto::biurs_v1::ListResponse) -> Result<Self, Self::Error> {
        value
            .list
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<Vec<_>, _>>()
    }
}

impl From<Vec<crate::types::Metadata>> for crate::proto::biurs_v1::ListResponse {
    fn from(value: Vec<crate::types::Metadata>) -> Self {
        Self {
            list: value.into_iter().map(Into::into).collect(),
        }
    }
}
