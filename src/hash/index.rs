macro_rules! impl_index {
    ($idx: ty, $struct: ident, $i: tt, Output = $output: ty, Params = [$($type:ident : $trait:ident),*], Constants = $($constgen:ident),*) => {
        impl<$($type: $trait,)* $(const $constgen: usize,)*> core::ops::Index<$idx> for $struct<$($type,)* $($constgen,)*> {
            type Output = $output;

            fn index(&self, index: $idx) -> &Self::Output {
                &self.$i[index]
            }
        }

        impl<$($type: $trait,)* $(const $constgen: usize,)*> core::ops::IndexMut<$idx> for $struct<$($type,)* $($constgen,)*> {

            fn index_mut(&mut self, index: $idx) -> &mut Self::Output {
                &mut self.$i[index]
            }
        }
    };
}

macro_rules! impl_indexing {
    ($struct: ident, $field: tt, Output = $output: ty, Params = [$($type:ident : $trait:ident),*], Constants = [$($constgen:ident),*]) => {
        crate::hash::index::impl_index!(usize, $struct, $field, Output = $output, Params = [$($type : $trait),*], Constants = $($constgen),*);
        crate::hash::index::impl_index!(core::ops::RangeTo<usize>, $struct, $field, Output = [$output], Params = [$($type : $trait),*], Constants = $($constgen),*);
        crate::hash::index::impl_index!(core::ops::Range<usize>, $struct, $field, Output = [$output], Params = [$($type : $trait),*], Constants = $($constgen),*);
        crate::hash::index::impl_index!(core::ops::RangeFrom<usize>, $struct, $field, Output = [$output], Params = [$($type : $trait),*], Constants = $($constgen),*);
    }
}

pub(crate) use {impl_index, impl_indexing};
