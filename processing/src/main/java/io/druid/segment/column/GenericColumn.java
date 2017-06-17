/*
 * Licensed to Metamarkets Group Inc. (Metamarkets) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. Metamarkets licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package io.druid.segment.column;

import io.druid.query.monomorphicprocessing.CalledFromHotLoop;
import io.druid.query.monomorphicprocessing.HotLoopCallee;
import io.druid.segment.DoubleColumnSelector;
import io.druid.segment.FloatColumnSelector;
import io.druid.segment.LongColumnSelector;
import io.druid.segment.data.ReadableOffset;

import java.io.Closeable;

/**
 */
public interface GenericColumn extends HotLoopCallee, Closeable
{
  public int length();
  public ValueType getType();
  public boolean hasMultipleValues();

  @CalledFromHotLoop
  public String getStringSingleValueRow(int rowNum);

  @CalledFromHotLoop
  float getFloatSingleValueRow(int rowNum);
  FloatColumnSelector makeFloatSingleValueRowSelector(ReadableOffset offset);

  @CalledFromHotLoop
  long getLongSingleValueRow(int rowNum);
  LongColumnSelector makeLongSingleValueRowSelector(ReadableOffset offset);

  @CalledFromHotLoop
  double getDoubleSingleValueRow(int rowNum);
  DoubleColumnSelector makeDoubleSingleValueRowSelector(ReadableOffset offset);

  @CalledFromHotLoop
  boolean isNull(int rowNum);

  @Override
  void close();
}
